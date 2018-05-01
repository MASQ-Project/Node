// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use actix::Actor;
use actix::Context;
use actix::SyncAddress;
use actix::Handler;
use actix::Subscriber;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::hopper::HopperTemporaryTransmitDataMsg;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use stream_handler_pool::PoolBindMessage;

pub struct Dispatcher {
    to_proxy_server: Option<Box<Subscriber<InboundClientData> + Send>>,
    to_hopper: Option<Box<Subscriber<InboundClientData> + Send>>,
    to_stream: Option<Box<Subscriber<TransmitDataMsg> + Send>>,
    logger: Logger,
}

impl Actor for Dispatcher {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.to_proxy_server = Some(msg.peer_actors.proxy_server.from_dispatcher);
        self.to_hopper = Some(msg.peer_actors.hopper.from_dispatcher);
        ()
    }
}

impl Handler<PoolBindMessage> for Dispatcher {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: PoolBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.to_stream = Some(msg.stream_handler_pool_subs.transmit_sub);
        Ok (())
    }
}

impl Handler<InboundClientData> for Dispatcher {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        match msg.component {
            Component::ProxyServer => self.to_proxy_server.as_ref().expect("ProxyServer unbound in Dispatcher").send(msg).expect("ProxyServer is dead"),
            Component::Hopper => unimplemented!(),
            _ => {
                // crashpoint - StreamHandlerPool should never send us anything else, so panic! may make sense
                panic! ("{:?} should not be receiving traffic from Dispatcher", msg.component)
            }
        };
        ()
    }
}

// TODO when we are decentralized, remove this handler
impl Handler<HopperTemporaryTransmitDataMsg> for Dispatcher {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: HopperTemporaryTransmitDataMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug (format! ("Echoing {} bytes from Hopper to Hopper", msg.data.len ()));
        let ibcd = InboundClientData {
            last_data: msg.last_data,
            data: msg.data,
            socket_addr: SocketAddr::from_str("1.2.3.4:5678").expect("Couldn't create SocketAddr from 1.2.3.4:5678"),
            component: Component::Hopper,
            origin_port: None,
        };
        self.to_hopper.as_ref().expect("Hopper unbound in Dispatcher").send(ibcd).expect("Hopper is dead");
        Ok(())
    }
}

impl Handler<TransmitDataMsg> for Dispatcher {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug (format! ("Relaying {} bytes from ProxyServer to StreamHandlerPool", msg.data.len ()));
        self.to_stream.as_ref().expect("StreamHandlerPool unbound in Dispatcher").send(msg).expect("StreamHandlerPool is dead");
        Ok(())
    }
}

impl Dispatcher {
    pub fn new () -> Dispatcher {
        Dispatcher {
            to_proxy_server: None,
            to_stream: None,
            to_hopper: None,
            logger: Logger::new ("Dispatcher"),
        }
    }

    pub fn make_subs_from (addr: &SyncAddress<Dispatcher>) -> DispatcherSubs {
        DispatcherSubs {
            ibcd_sub: addr.subscriber::<InboundClientData>(),
            bind: addr.subscriber::<BindMessage>(),
            from_proxy_server: addr.subscriber::<TransmitDataMsg>(),
            from_hopper: addr.subscriber::<HopperTemporaryTransmitDataMsg>(),
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::net::SocketAddr;
    use actix::Arbiter;
    use actix::msgs;
    use actix::System;
    use sub_lib::dispatcher::Endpoint;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::make_peer_actors;
    use test_utils::test_utils::make_peer_actors_from;
    use node_test_utils::make_stream_handler_pool_subs_from;

    #[test]
    fn sends_inbound_data_for_proxy_server_to_proxy_server() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_ibcd = subject_addr.subscriber::<InboundClientData> ();
        let proxy_server = Recorder::new();
        let recording_arc = proxy_server.get_recording();
        let awaiter = proxy_server.get_awaiter();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let origin_port = Some (8080);
        let component = Component::ProxyServer;
        let data: Vec<u8> = vec! (9, 10, 11);
        let ibcd_in = InboundClientData {
            socket_addr,
            origin_port,
            component,
            last_data: false,
            data: data.clone ()
        };
        let mut peer_actors = make_peer_actors_from(Some(proxy_server), None, None, None);
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.send( BindMessage { peer_actors });

        subject_ibcd.send (ibcd_in).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();

        let message = &recording.get_record::<InboundClientData>(0) as *const _;
        let (actual_socket_addr, actual_component, actual_data) = unsafe {
            let tptr = message as *const Box<InboundClientData>;
            let message = &*tptr;
            (message.socket_addr, message.component, message.data.clone ())
        };

        assert_eq!(actual_component, component);
        assert_eq!(actual_socket_addr, socket_addr);
        assert_eq!(actual_data, data);
        assert_eq! (recording.len (), 1);
    }

    #[test]
    #[should_panic (expected = "Neighborhood should not be receiving traffic from Dispatcher")]
    fn panics_if_it_encounters_inbound_traffic_for_neighborhood() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_ibcd = subject_addr.subscriber::<InboundClientData> ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:8765").unwrap ();
        let origin_port = Some (80);
        let component = Component::Neighborhood;
        let data: Vec<u8> = vec! (9, 10, 11);
        let ibcd_in = InboundClientData {
            socket_addr,
            origin_port,
            component,
            last_data: false,
            data: data.clone ()
        };
        let mut peer_actors = make_peer_actors();
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.send( BindMessage { peer_actors });

        subject_ibcd.send (ibcd_in).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
    }

    #[test]
    #[should_panic (expected = "ProxyClient should not be receiving traffic from Dispatcher")]
    fn panics_if_it_encounters_inbound_traffic_for_proxy_client() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_ibcd = subject_addr.subscriber::<InboundClientData> ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:8765").unwrap ();
        let origin_port = Some (22);
        let component = Component::ProxyClient;
        let data: Vec<u8> = vec! (9, 10, 11);
        let ibcd_in = InboundClientData {
            socket_addr,
            origin_port,
            component,
            last_data: false,
            data: data.clone ()
        };
        let mut peer_actors = make_peer_actors();
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        subject_addr.send( BindMessage { peer_actors });

        subject_ibcd.send (ibcd_in).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
    }

    #[test]
    #[should_panic (expected = "ProxyServer unbound in Dispatcher")]
    fn panics_when_proxy_server_is_unbound() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_ibcd = subject_addr.subscriber::<InboundClientData> ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:8765").unwrap ();
        let origin_port = Some (1234);
        let component = Component::ProxyServer;
        let data: Vec<u8> = vec! (9, 10, 11);
        let ibcd_in = InboundClientData {
            socket_addr,
            origin_port,
            component,
            last_data: false,
            data: data.clone ()
        };

        subject_ibcd.send (ibcd_in).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
    }

    #[test]
    #[should_panic (expected = "StreamHandlerPool unbound in Dispatcher")]
    fn panics_when_stream_handler_pool_is_unbound() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_obcd = subject_addr.subscriber::<TransmitDataMsg> ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let data: Vec<u8> = vec! (9, 10, 11);
        let obcd = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            data: data.clone ()
        };

        subject_obcd.send (obcd).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
    }

    #[test]
    #[should_panic (expected = "Hopper unbound in Dispatcher")]
    fn panics_when_hopper_is_unbound() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let data: Vec<u8> = vec! (9, 10, 11);
        let transmit_msg = HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            data: data.clone ()
        };

        subject_addr.send (transmit_msg);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
    }

    #[test]
    fn forwards_outbound_data_to_stream_handler_pool() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_obcd = subject_addr.subscriber::<TransmitDataMsg> ();
        let stream_handler_pool = Recorder::new();
        let recording_arc = stream_handler_pool.get_recording();
        let awaiter = stream_handler_pool.get_awaiter();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let data: Vec<u8> = vec! (9, 10, 11);
        let obcd = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            data: data.clone ()
        };
        let mut peer_actors = make_peer_actors_from(None, None, None, None);
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        let stream_handler_pool_subs = make_stream_handler_pool_subs_from (Some (stream_handler_pool));
        subject_addr.send( PoolBindMessage { dispatcher_subs: peer_actors.dispatcher.clone (), stream_handler_pool_subs});
        subject_addr.send( BindMessage { peer_actors });

        subject_obcd.send (obcd).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();

        let message = &recording.get_record::<TransmitDataMsg>(0) as *const _;
        let (actual_endpoint, actual_data) = unsafe {
            let tptr = message as *const Box<TransmitDataMsg>;
            let message = &*tptr;
            (message.endpoint.clone(), message.data.clone ())
        };

        assert_eq!(actual_endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(actual_data, data);
        assert_eq! (recording.len (), 1);
    }

    #[test]
    fn converts_nonterminal_hopper_temporary_transmit_data_msg_to_inbound_client_data_for_hopper() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let stream_handler_pool = Recorder::new();
        let hopper = Recorder::new();
        let recording_arc = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let data: Vec<u8> = vec! (9, 10, 11);
        let transmit_msg = HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            data: data.clone ()
        };
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper), None);
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        let stream_handler_pool_subs = make_stream_handler_pool_subs_from (Some (stream_handler_pool));
        subject_addr.send( PoolBindMessage { dispatcher_subs: peer_actors.dispatcher.clone (), stream_handler_pool_subs});
        subject_addr.send( BindMessage { peer_actors });

        subject_addr.send (transmit_msg);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();

        let message = &recording.get_record::<InboundClientData>(0) as *const _;
        let (actual_component, actual_last_data, actual_data) = unsafe {
            let tptr = message as *const Box<InboundClientData>;
            let message = &*tptr;
            (message.component.clone(), message.last_data, message.data.clone ())
        };

        assert_eq!(actual_component, Component::Hopper);
        assert_eq!(false, actual_last_data);
        assert_eq!(actual_data, data);
        assert_eq!(recording.len (), 1);
    }
    #[test]
    fn converts_terminal_hopper_temporary_transmit_data_msg_to_inbound_client_data_for_hopper() {
        let system = System::new ("test");
        let subject = Dispatcher::new ();
        let subject_addr: SyncAddress<_> = subject.start ();
        let stream_handler_pool = Recorder::new();
        let hopper = Recorder::new();
        let recording_arc = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let data: Vec<u8> = vec! (9, 10, 11);
        let transmit_msg = HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: true,
            data: data.clone ()
        };
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper), None);
        peer_actors.dispatcher = Dispatcher::make_subs_from(&subject_addr);
        let stream_handler_pool_subs = make_stream_handler_pool_subs_from (Some (stream_handler_pool));
        subject_addr.send( PoolBindMessage { dispatcher_subs: peer_actors.dispatcher.clone (), stream_handler_pool_subs});
        subject_addr.send( BindMessage { peer_actors });

        subject_addr.send (transmit_msg);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();

        let message = &recording.get_record::<InboundClientData>(0) as *const _;
        let (actual_component, actual_last_data, actual_data) = unsafe {
            let tptr = message as *const Box<InboundClientData>;
            let message = &*tptr;
            (message.component.clone(), message.last_data, message.data.clone ())
        };

        assert_eq!(actual_component, Component::Hopper);
        assert_eq!(true, actual_last_data);
        assert_eq!(actual_data, data);
        assert_eq!(recording.len (), 1);
    }
}
