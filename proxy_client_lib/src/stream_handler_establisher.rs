// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::io::Error;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::thread;
use sub_lib::tcp_wrappers::TcpStreamWrapperFactory;
use actix::Subscriber;
use stream_handler_pool::StreamHandlerPoolReal;
use stream_reader::StreamReader;
use stream_writer::StreamWriter;
use sub_lib::cryptde::StreamKey;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::error::ResolveError;

pub struct StreamHandlerEstablisher {
    pub tcp_stream_wrapper_factory: Box<TcpStreamWrapperFactory>,
    pub hopper_sub: Box<Subscriber<IncipientCoresPackage> + Send>,
    pub stream_adder_tx: Sender<(StreamKey, StreamWriter)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub logger: Logger
}

impl StreamHandlerEstablisher {
    pub fn new (pool: &StreamHandlerPoolReal) -> StreamHandlerEstablisher {
        StreamHandlerEstablisher {
            tcp_stream_wrapper_factory: pool.tcp_stream_wrapper_factory.dup (),
            hopper_sub: pool.hopper_sub.clone (),
            stream_adder_tx: pool.stream_adder_tx.clone (),
            stream_killer_tx: pool.stream_killer_tx.clone (),
            logger: Logger::new ("Proxy Client")
        }
    }

    pub fn after_resolution (&mut self, payload: &ClientRequestPayload, package: &ExpiredCoresPackage, lookup_result: Result<LookupIp, ResolveError>) -> io::Result<StreamWriter> {
        let target_hostname = payload.target_hostname.clone ().expect ("Internal error: DNS resolution succeeded on missing hostname");
        let ip_addrs: Vec<IpAddr> = match lookup_result {
            Err (e) => {
                self.logger.error (format! ("Could not find IP address for host {}: {}", target_hostname, e));
                return Err (Error::from (e))
            },
            Ok (lookup_ip) => lookup_ip.iter ().map (|x| x).collect ()
        };
        self.logger.debug (format! ("Found IP addresses for {}: {:?}", target_hostname, &ip_addrs));
        let mut stored_write_stream = self.tcp_stream_wrapper_factory.make ();
        match StreamHandlerPoolReal::connect_stream (&mut stored_write_stream, ip_addrs, &target_hostname, payload.target_port, &self.logger) {
            Err (e) => return Err (e),
            Ok (()) => ()
        }
        match stored_write_stream.set_read_timeout (None) {
            Err (e) => {
                let target = match stored_write_stream.peer_addr () {
                    Ok (s) => format! ("{}", s),
                    Err (_) => target_hostname.clone ()
                };
                self.logger.error (format! ("Could not set the read timeout for connection to {}", target));
                return Err (e)
            },
            Ok (()) => ()
        }
        self.logger.debug (format! ("New stream set to block for reads"));
        match self.spawn_stream_reader (package, payload, &stored_write_stream) {
            Err (e) => return Err (e),
            Ok (_) => ()
        }
        let stream_writer = StreamWriter::new (stored_write_stream);
        let returned_write_stream = stream_writer.clone ();
        self.stream_adder_tx.send ((payload.stream_key, stream_writer)).expect("StreamHandlerPool died");
        Ok (returned_write_stream)
    }

    fn spawn_stream_reader (&self, package: &ExpiredCoresPackage, payload: &ClientRequestPayload, write_stream: &Box<TcpStreamWrapper>) -> io::Result<()> {
        let read_stream = match write_stream.try_clone () {
            Err (e) => {self.logger.error (format! ("Could not clone stream: {}", e)); return Err (e)},
            Ok (s) => s
        };
        let framer = StreamHandlerPoolReal::framer_from_protocol (payload.protocol);
        let peer_addr = match (&read_stream).peer_addr () {Ok (a) => format! ("{}", a), Err (_) => format! ("<unknown>")};
        let mut stream_reader = StreamReader::new (
            payload.stream_key,
            self.hopper_sub.clone (),
            read_stream,
            self.stream_killer_tx.clone (),
            peer_addr.clone (),
            package.remaining_route.clone (),
            framer,
            payload.originator_public_key.clone (),
        );
        self.logger.debug (format! ("Spawning StreamReader for {}", peer_addr));
        thread::spawn(move || {
            stream_reader.run();
        });
        Ok (())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use actix::System;
    use serde_cbor;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::cryptde::PlainData;
    use sub_lib::proxy_server::ProxyProtocol;
    use sub_lib::cryptde::Key;
    use sub_lib::proxy_client::ClientResponsePayload;
    use test_utils::test_utils;
    use test_utils::test_utils::Recorder;
    use local_test_utils::TcpStreamWrapperMock;
    use local_test_utils::ResolverWrapperMock;


    #[test]
    fn spawn_stream_reader_handles_http () {
        let hopper = Recorder::new ();
        let awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        let (tx, rx) = mpsc::channel::<io::Result<()>> ();
        thread::spawn(move || {
            let system = System::new ("test");
            let hopper_sub = test_utils::make_peer_actors_from (None, None, Some (hopper), None).hopper.from_hopper_client;
            let read_stream = Box::new (TcpStreamWrapperMock::new ()
                .peer_addr_result (Ok (SocketAddr::from_str ("1.2.3.4:5678").unwrap ()))
                .read_buffer (vec! (0x16, 0x03, 0x03, 0x00, 0x00))
                .read_result (Ok (5))
                .read_buffer (b"HTTP/1.1 200 OK\r\n\r\n".to_vec ())
                .read_result (Ok (19))
                .read_result (Err (Error::from (ErrorKind::BrokenPipe))));
            let stored_write_stream: Box<TcpStreamWrapper> = Box::new(TcpStreamWrapperMock::new ()
                .try_clone_result (Ok (read_stream)));
            let pool = StreamHandlerPoolReal::new(Box::new(ResolverWrapperMock::new()),
                                                  Box::new(CryptDENull::new()), hopper_sub);
            let subject = StreamHandlerEstablisher::new(&pool);

            let result = subject.spawn_stream_reader(
                &ExpiredCoresPackage::new(test_utils::make_meaningless_route(), PlainData::new(&[])),
                &ClientRequestPayload {
                    stream_key: SocketAddr::from_str("255.255.255.255:65535").unwrap(),
                    last_data: false,
                    data: PlainData::new(&[]),
                    target_hostname: Some("blah".to_string()),
                    target_port: 0,
                    protocol: ProxyProtocol::HTTP,
                    originator_public_key: Key::new(&[]),
                },
                &stored_write_stream
            );
            tx.send (result).is_ok ();
            system.run ();
        });
        rx.recv ().unwrap ().expect ("spawn_stream_reader () failed");
        awaiter.await_message_count (1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let response = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (response.last_response, false);
        assert_eq! (response.data.data, b"HTTP/1.1 200 OK\r\n\r\n".to_vec ());
    }

    #[test]
    fn spawn_stream_reader_handles_tls () {
        let hopper = Recorder::new ();
        let awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        let (tx, rx) = mpsc::channel::<io::Result<()>> ();
        thread::spawn(move || {
            let system = System::new ("test");
            let hopper_sub = test_utils::make_peer_actors_from (None, None, Some (hopper), None).hopper.from_hopper_client;
            let read_stream = Box::new (TcpStreamWrapperMock::new ()
                .peer_addr_result (Ok (SocketAddr::from_str ("1.2.3.4:5678").unwrap ()))
                .read_buffer (b"HTTP/1.1 200 OK\r\n\r\n".to_vec ())
                .read_result (Ok (19))
                .read_buffer (vec! (0x16, 0x03, 0x03, 0x00, 0x00))
                .read_result (Ok (5))
                .read_result (Err (Error::from (ErrorKind::BrokenPipe))));
            let stored_write_stream: Box<TcpStreamWrapper> = Box::new(TcpStreamWrapperMock::new ()
                .try_clone_result (Ok (read_stream)));
            let pool = StreamHandlerPoolReal::new(Box::new(ResolverWrapperMock::new()),
                                                  Box::new(CryptDENull::new()), hopper_sub);
            let subject = StreamHandlerEstablisher::new(&pool);

            let result = subject.spawn_stream_reader(
                &ExpiredCoresPackage::new(test_utils::make_meaningless_route(), PlainData::new(&[])),
                &ClientRequestPayload {
                    stream_key: SocketAddr::from_str("255.255.255.255:65535").unwrap(),
                    last_data: false,
                    data: PlainData::new(&[]),
                    target_hostname: None,
                    target_port: 0,
                    protocol: ProxyProtocol::TLS,
                    originator_public_key: Key::new(&[]),
                },
                &stored_write_stream
            );
            tx.send (result).is_ok ();
            system.run ();
        });
        rx.recv ().unwrap ().expect ("spawn_stream_reader () failed");
        awaiter.await_message_count (1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let response = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (response.last_response, false);
        assert_eq! (response.data.data, vec! (0x16, 0x03, 0x03, 0x00, 0x00));
    }
}