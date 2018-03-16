// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use actix::Actor;
use actix::Context;
use actix::SyncAddress;
use actix::Handler;
use actix::Subscriber;
use sub_lib::actor_messages::ResponseMessage;
use sub_lib::actor_messages::BindMessage;
use sub_lib::actor_messages::RequestMessage;
use sub_lib::actor_messages::TemporaryBindMessage;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::dispatcher::DispatcherFacadeSubs;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::TransmitterHandle;
use sub_lib::cryptde::PlainData;
use sub_lib::logger::Logger;

pub struct DispatcherFacade {
    ibcd_transmitter: Sender<InboundClientData>,
    to_proxy_server: Option<Box<Subscriber<RequestMessage> + Send>>,
    ps_transmitter_handle: Option<Box<TransmitterHandle>>,
    logger: Logger,
}

impl Actor for DispatcherFacade {
    type Context = Context<Self>;
}

impl DispatcherFacade {
    pub fn new (ibcd_transmitter: Sender<InboundClientData>) -> DispatcherFacade {
        DispatcherFacade {
            ibcd_transmitter,
            to_proxy_server: None,
            ps_transmitter_handle: None,
            logger: Logger::new ("Dispatcher"),
        }
    }

    pub fn make_subs_from (addr: &SyncAddress<DispatcherFacade>) -> DispatcherFacadeSubs {
        DispatcherFacadeSubs {
            ibcd_sub: addr.subscriber::<InboundClientData>(),
            bind: addr.subscriber::<BindMessage>(),
            from_proxy_server: addr.subscriber::<ResponseMessage>(),
            transmitter_bind: addr.subscriber::<TemporaryBindMessage>(),
        }
    }
}

impl Handler<InboundClientData> for DispatcherFacade {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        match msg.component {
            Component::ProxyServer => {
                if let Some(ref proxy_server) =  self.to_proxy_server {
                    proxy_server.send(RequestMessage { data: (Endpoint::Socket(msg.socket_addr), msg.component, msg.data) }).is_ok()
                } else {
                    panic!("Dispatcher Facade has not been bound");
                }
            },
            _ => {
                self.ibcd_transmitter.send (msg).is_ok ()
            }
        };
        ()
    }
}

impl Handler<BindMessage> for DispatcherFacade {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.to_proxy_server = Some(msg.peer_actors.proxy_server.from_dispatcher);
        ()
    }
}

impl Handler<ResponseMessage> for DispatcherFacade {
    type Result = ();

    fn handle(&mut self, msg: ResponseMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug (format! ("Relaying {} bytes from Proxy Server to Dispatcher", msg.data.len ()));
        self.ps_transmitter_handle.as_ref().expect("Proxy Server transmitter unbound").transmit_to_socket_addr(
            msg.socket_addr,
            PlainData::new(msg.data.as_slice())
        );
        ()
    }
}

impl Handler<TemporaryBindMessage> for DispatcherFacade {
    type Result = ();

    fn handle(&mut self, msg: TemporaryBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.ps_transmitter_handle = Some(msg.transmitter_handle);
        ()
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::str::FromStr;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use sub_lib::test_utils::Recorder;
    use sub_lib::actor_messages::RequestMessage;
    use sub_lib::dispatcher::Endpoint;
    use test_utils::to_string;
    use sub_lib::test_utils::TransmitterHandleMock;
    use sub_lib::test_utils::make_peer_actors_from;
    use sub_lib::test_utils::make_peer_actors;

    #[test]
    fn converts_ibcd_actor_message_to_ibcd_channel_message () {
        let system = System::new ("test");
        let (ibcd_transmitter, ibcd_receiver) = mpsc::channel ();
        let subject = DispatcherFacade::new (ibcd_transmitter);
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_sub = subject_addr.subscriber::<InboundClientData> ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let component = Component::Hopper;
        let data: Vec<u8> = vec! (9, 10, 11);
        let ibcd_in = InboundClientData {socket_addr, component, data: data.clone ()};

        subject_sub.send (ibcd_in).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
        let ibcd_out = ibcd_receiver.recv ().unwrap ();
        assert_eq! (ibcd_out.socket_addr, socket_addr);
        assert_eq! (ibcd_out.component, component);
        assert_eq! (ibcd_out.data, data);
    }

    #[test]
    fn sends_inbound_proxy_server_traffic_directly_via_actor_system() {
        let system = System::new ("test");
        let (ibcd_transmitter, _ibcd_receiver) = mpsc::channel ();
        let subject = DispatcherFacade::new (ibcd_transmitter);
        let subject_addr: SyncAddress<_> = subject.start ();
        let subject_ibcd = subject_addr.subscriber::<InboundClientData> ();
        let proxy_server = Recorder::new();
        let recording_arc = proxy_server.get_recording();
        let awaiter = proxy_server.get_awaiter();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let component = Component::ProxyServer;
        let data: Vec<u8> = vec! (9, 10, 11);
        let ibcd_in = InboundClientData {socket_addr, component, data: data.clone ()};
        let mut peer_actors = make_peer_actors_from(Some(proxy_server), None, None, None);
        peer_actors.dispatcher = DispatcherFacade::make_subs_from(&subject_addr);
        subject_addr.send( BindMessage { peer_actors });

        subject_ibcd.send (ibcd_in).unwrap ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();

        let message = &recording.get_record::<RequestMessage>(0) as *const _;
        let (actual_socket_addr, actual_component, actual_data) = unsafe {
            let tptr = message as *const Box<RequestMessage>;
            let message = &*tptr;
            message.data.clone ()
        };

        assert_eq!(actual_component, component);
        assert_eq!(actual_socket_addr, Endpoint::Socket(socket_addr));
        assert_eq!(actual_data, data);
        assert_eq! (recording.len (), 1);
    }

    #[test]
    fn sends_outbound_proxy_server_traffic_back_to_dispatcher() {
        let system = System::new ("test");
        let (ibcd_transmitter, _ibcd_receiver) = mpsc::channel ();
        let transmitter_handle = TransmitterHandleMock::new ();
        let transmitter_handle_log = transmitter_handle.log.clone ();
        let subject = DispatcherFacade::new (ibcd_transmitter);
        let subject_addr: SyncAddress<_> = subject.start ();
        let socket_addr = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let data: Vec<u8> = vec! (9, 10, 11);

        let mut peer_actors = make_peer_actors();
        peer_actors.dispatcher = DispatcherFacade::make_subs_from(&subject_addr);
        subject_addr.send( BindMessage { peer_actors });
        subject_addr.send( TemporaryBindMessage { transmitter_handle: Box::new(transmitter_handle) });

        subject_addr.send (ResponseMessage { socket_addr, data: data.clone() });

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        assert_eq! (transmitter_handle_log.dump (), vec! (format!("transmit_to_socket_addr: to_socket_addr: V4(1.2.3.4:5678), data: {:?}",
                                                                  to_string(&data)).as_str()));
    }
}
