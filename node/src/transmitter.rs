// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::marker::Send;
use actix::Subscriber;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::DispatcherError;
use sub_lib::dispatcher::OutboundClientData;
use sub_lib::dispatcher::TransmitterHandle;
use sub_lib::dispatcher::Endpoint;
use sub_lib::limiter::Limiter;
use sub_lib::logger::Logger;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::node_addr::NodeAddr;
use sub_lib::utils;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;
use sub_lib::stream_handler_pool::TransmitDataMsg;

pub trait Transmitter: Send {
    fn make_handle (&mut self, component: Component, data_sender: &Sender<OutboundClientData>) -> TransmitterHandleReal;
    fn handle_traffic (&mut self);
}

pub struct TransmitterReal {
    obcd_receiver: Receiver<OutboundClientData>,
    transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
    neighborhood_arc: Arc<Mutex<Neighborhood>>,
    limiter: Limiter,
    logger: Logger
}

impl Transmitter for TransmitterReal {
    fn make_handle (&mut self, component: Component, data_sender: &Sender<OutboundClientData>) -> TransmitterHandleReal {
        TransmitterHandleReal::new (component, data_sender)
    }

    fn handle_traffic (&mut self) {
        while self.limiter.should_continue () {
            let (target, _from, data) = match self.obcd_receiver.recv () {
                Ok (c) => c,
                Err (_) => {
                    self.logger.log(String::from("No data to transmit: all clients died!"));
                    return
                }
            };

            let neighborhood = match self.neighborhood_arc.as_ref().lock() {
                Ok(n) => n,
                Err(_) => return
            };

            let node_addr = match target {
                Endpoint::Key (key) => {
                    match neighborhood.node_addr_from_public_key (&key.data[..]) {
                        None => {
                            self.logger.log(format!("Cannot transmit to key {}: no NodeAddr known",
                                                    utils::make_hex_string(&key.data[..])));
                            continue
                        },
                        Some(node_addr) => node_addr
                    }
                },
                Endpoint::Ip (ip_addr) => match neighborhood.node_addr_from_ip_address (&ip_addr) {
                    None => {
                        unimplemented!()
                    },
                    Some (node_addr) => node_addr
                },
                Endpoint::Socket (socket_addr) => NodeAddr::from (&socket_addr)
            };
            // TODO: Taking just the first address should be eliminated when this moves into the StreamHandlerPool.
            let mut socket_addrs: Vec<SocketAddr> = node_addr.into ();
            self.transmit_sub.send (TransmitDataMsg {socket_addr: socket_addrs.remove (0), data}).expect ("Internal error");
        }
    }
}

pub trait TransmitterFactory: Send {
    fn make (&self, obcd_receiver: Receiver<OutboundClientData>,
             transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
             neighborhood_arc: Arc<Mutex<Neighborhood>>) -> Box<Transmitter>;
}

pub struct TransmitterFactoryReal {}

impl TransmitterFactory for TransmitterFactoryReal {
    fn make(&self, obcd_receiver: Receiver<OutboundClientData>,
            transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
            neighborhood_arc: Arc<Mutex<Neighborhood>>) -> Box<Transmitter> {
        Box::new (TransmitterReal {
            obcd_receiver,
            transmit_sub,
            neighborhood_arc,
            limiter: Limiter::new (),
            logger: Logger::new ("Transmitter"),
        })
    }
}

impl TransmitterFactoryReal {
    pub fn new () -> TransmitterFactoryReal {
        TransmitterFactoryReal {}
    }
}

pub struct TransmitterHandleReal {
    component: Component,
    data_sender: Sender<OutboundClientData>,
}

impl TransmitterHandle for TransmitterHandleReal {
    fn transmit(&self, to_public_key: &Key, data: PlainData) -> Result<(), DispatcherError> {
        self.transmit_triple((Endpoint::Key (to_public_key.clone ()), self.component,
                              data.data))
    }

    fn transmit_to_ip(&self, to_ip_addr: IpAddr, data: PlainData) -> Result<(), DispatcherError> {
        self.transmit_triple((Endpoint::Ip (to_ip_addr), self.component, data.data))
    }

    fn transmit_to_socket_addr (&self, to_socket_addr: SocketAddr, data: PlainData) -> Result<(), DispatcherError> {
        self.transmit_triple((Endpoint::Socket (to_socket_addr), self.component, data.data))
    }
}

impl TransmitterHandleReal {
    pub fn new (component: Component, data_sender: &Sender<OutboundClientData>) -> TransmitterHandleReal {
        TransmitterHandleReal {component, data_sender: data_sender.clone ()}
    }

    fn transmit_triple (&self, data: OutboundClientData) -> Result<(), DispatcherError> {
        match self.data_sender.send (data) {
            Ok (_) => Ok (()),
            Err (_) => return Err (DispatcherError::TransmitterPanicked)
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::sync::mpsc::TryRecvError;
    use std::str::FromStr;
    use std::thread;
    use actix::Actor;
    use actix::System;
    use actix::Arbiter;
    use actix::SyncAddress;
    use actix::msgs;
    use sub_lib::logger::LoggerInitializerWrapper;
    use sub_lib::test_utils::TestLogHandler;
    use sub_lib::test_utils::LoggerInitializerWrapperMock;
    use test_utils::NeighborhoodNull;
    use sub_lib::test_utils::Recorder;
    use sub_lib::test_utils::Recording;
    use sub_lib::test_utils::RecordAwaiter;

    #[test]
    fn transmitter_transmits () {
        let system = System::new ("test");
        let mut neighborhood = NeighborhoodNull::new (vec! (
            ("35.69.103.137", &[1234, 2345], "one key"),
            ("35.69.103.138", &[3456], "another key"),
        ));
        neighborhood.bound = true;
        let (mut subject, obcd_transmitter, recording_arc, _)
            = make_transmitter (neighborhood, 4);
        obcd_transmitter.send((Endpoint::Key (Key::new (b"one key")), Component::Hopper,
                               Vec::from("hopper1".as_bytes ()))).unwrap ();
        obcd_transmitter.send((Endpoint::Key (Key::new (b"another key")), Component::Neighborhood,
                               Vec::from("neighborhood".as_bytes ()))).unwrap ();
        obcd_transmitter.send((Endpoint::Ip (IpAddr::from_str ("35.69.103.137").unwrap ()), Component::Hopper,
                               Vec::from("hopper2".as_bytes ()))).unwrap ();
        obcd_transmitter.send((Endpoint::Socket (SocketAddr::from_str ("35.69.103.140:4567").unwrap ()), Component::ProxyClient,
                               Vec::from("proxyclient".as_bytes ()))).unwrap ();

        subject.handle_traffic ();

        Arbiter::system ().send (msgs::SystemExit (0));
        system.run ();
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.get_record::<TransmitDataMsg>(0), &TransmitDataMsg {
            socket_addr: SocketAddr::from_str ("35.69.103.137:1234").unwrap (),
            data: Vec::from ("hopper1".as_bytes ())
        });
        assert_eq! (recording.get_record::<TransmitDataMsg>(1), &TransmitDataMsg {
            socket_addr: SocketAddr::from_str ("35.69.103.138:3456").unwrap (),
            data: Vec::from ("neighborhood".as_bytes ())
        });
        assert_eq! (recording.get_record::<TransmitDataMsg>(2), &TransmitDataMsg {
            socket_addr: SocketAddr::from_str ("35.69.103.137:1234").unwrap (),
            data: Vec::from ("hopper2".as_bytes ())
        });
        assert_eq! (recording.get_record::<TransmitDataMsg>(3), &TransmitDataMsg {
            socket_addr: SocketAddr::from_str ("35.69.103.140:4567").unwrap (),
            data: Vec::from ("proxyclient".as_bytes ())
        });
        assert_eq! (recording.len (), 4)
    }

    #[test]
    fn transmitter_handles_unknown_public_key () {
        LoggerInitializerWrapperMock::new ().init ();
        let system = System::new ("test");
        let mut neighborhood = NeighborhoodNull::new (vec! ());
        neighborhood.bound = true;
        let (mut subject, obcd_transmitter, recording_arc, _)
            = make_transmitter (neighborhood, 2);
        obcd_transmitter.send((Endpoint::Key (Key::new (b"public key")), Component::Hopper,
                               Vec::from("hopper1".as_bytes ()))).unwrap ();
        obcd_transmitter.send((Endpoint::Key (Key::new (b"public key")), Component::Hopper,
                               Vec::from("hopper2".as_bytes ()))).unwrap ();

        subject.handle_traffic ();

        Arbiter::system ().send (msgs::SystemExit (0));
        system.run ();
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), 0);
        TestLogHandler::new ().exists_log_containing("ERROR: Transmitter: Cannot transmit to key 7075626C6963206B6579: no NodeAddr known");
    }

    #[test]
    fn transmitter_stops_if_neighborhood_panics () {
        let system = System::new ("test");
        let neighborhood = NeighborhoodNull::new (vec! ());
        let (mut subject, obcd_transmitter,
            recording_arc, _)
            = make_transmitter (neighborhood, 100);
        poison_arc_mutex(&subject.neighborhood_arc);
        obcd_transmitter.send((Endpoint::Key (Key::new (b"V4(35.69.103.137)")), Component::Neighborhood,
                               Vec::from("neighborhood".as_bytes ()))).unwrap ();

        subject.handle_traffic ();

        Arbiter::system ().send (msgs::SystemExit (0));
        system.run ();
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), 0);
    }

    #[test]
    fn transmitter_stops_if_all_clients_die () {
        LoggerInitializerWrapperMock::new ().init ();
        let _ = System::new ("test");
        let neighborhood = NeighborhoodNull::new (vec! ());
        let mut subject = {
            let (subject, _, _, _)
                = make_transmitter (neighborhood, 100);
            subject
        };

        subject.handle_traffic ();

        TestLogHandler::new ().exists_log_containing("ERROR: Transmitter: No data to transmit: all clients died!");
    }

    #[test]
    fn handle_generates_error_if_transmitter_dies_before_send () {
        let subject = {
            let (data_sender, _will_die) = mpsc::channel();
            TransmitterHandleReal::new (Component::Hopper, &data_sender)
        };

        let result = subject.transmit (&Key::new (&[]), PlainData::new (&[]));

        assert_eq! (result, Err (DispatcherError::TransmitterPanicked));
    }

    #[test]
    fn handle_sends_data_to_transmitter_on_transmit () {
        let (data_sender, data_receiver) = mpsc::channel ();
        let subject = TransmitterHandleReal {
            component: Component::ProxyClient,
            data_sender
        };

        let result = subject.transmit (&Key::new (b"public_key"), PlainData::new (b"data"));

        assert_eq! (result, Ok (()));
        assert_eq! (data_receiver.recv ().unwrap (), (Endpoint::Key (Key::new (b"public_key")),
                                                      Component::ProxyClient, Vec::from ("data".as_bytes ())));
        assert_eq! (data_receiver.try_recv (), Err (TryRecvError::Empty));
    }

    #[test]
    fn handle_sends_data_to_transmitter_on_transmit_to_ip () {
        let ip_addr = IpAddr::from_str ("4.5.6.7").unwrap ();
        let (data_sender, data_receiver) = mpsc::channel ();
        let subject = TransmitterHandleReal {
            component: Component::ProxyClient,
            data_sender
        };

        let result = subject.transmit_to_ip (ip_addr, PlainData::new (b"data"));

        assert_eq! (result, Ok (()));
        assert_eq! (data_receiver.recv ().unwrap (), (Endpoint::Ip (ip_addr), Component::ProxyClient,
                                                      Vec::from ("data".as_bytes ())));
        assert_eq! (data_receiver.try_recv (), Err (TryRecvError::Empty));
    }

    #[test]
    fn handle_sends_data_to_transmitter_on_transmit_to_socket_addr () {
        let socket_addr = SocketAddr::from_str ("4.5.6.7:8910").unwrap ();
        let (data_sender, data_receiver) = mpsc::channel ();
        let subject = TransmitterHandleReal {
            component: Component::ProxyClient,
            data_sender
        };

        let result = subject.transmit_to_socket_addr (socket_addr, PlainData::new (b"data"));

        assert_eq! (result, Ok (()));
        assert_eq! (data_receiver.recv ().unwrap (), (Endpoint::Socket (socket_addr), Component::ProxyClient,
                                                      Vec::from ("data".as_bytes ())));
        assert_eq! (data_receiver.try_recv (), Err (TryRecvError::Empty));
    }

    fn make_transmitter (neighborhood: NeighborhoodNull, limit: i32) -> (
            TransmitterReal,
            Sender<OutboundClientData>,
            Arc<Mutex<Recording>>,
            RecordAwaiter
        ) {
        let stream_handler_pool = Recorder::new ();
        let recording = stream_handler_pool.get_recording ();
        let awaiter = stream_handler_pool.get_awaiter();
        let stream_handler_pool_addr: SyncAddress<_> = stream_handler_pool.start ();
        let transmit_sub = stream_handler_pool_addr.subscriber::<TransmitDataMsg> ();
        let (obcd_transmitter, obcd_receiver) = mpsc::channel ();
        let transmitter = TransmitterReal {
            obcd_receiver,
            transmit_sub,
            neighborhood_arc: Arc::new (Mutex::new (neighborhood)),
            limiter: Limiter::with_only (limit),
            logger: Logger::new ("Transmitter")
        };
        (transmitter, obcd_transmitter, recording, awaiter)
    }

    fn poison_arc_mutex<T> (arc: &Arc<Mutex<T>>) where T: Send + ?Sized + 'static {
        let panickable = arc.clone ();
        let handle = thread::spawn (move || {
            let _t = panickable.as_ref ().lock ().unwrap ();
            panic! ();
        });
        handle.join ().err ();
        assert_eq! (arc.as_ref ().is_poisoned (), true);
    }
}
