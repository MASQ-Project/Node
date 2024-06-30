// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::discriminator::Discriminator;
use crate::discriminator::DiscriminatorFactory;
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::stream_messages::*;
use crate::sub_lib::dispatcher;
use crate::sub_lib::dispatcher::StreamShutdownMsg;
use crate::sub_lib::sequencer::Sequencer;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use actix::Recipient;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamReaderReal {
    stream: Box<dyn ReadHalfWrapper>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    reception_port: Option<u16>,
    ibcd_sub: Recipient<dispatcher::InboundClientData>,
    remove_sub: Recipient<RemoveStreamMsg>,
    dispatcher_stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    discriminators: Vec<Discriminator>,
    is_clandestine: bool,
    logger: Logger,
    sequencer: Sequencer,
}

impl Future for StreamReaderReal {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<()>, ()> {
        let mut buf = [0u8; 0x0001_0000];
        loop {
            match self.stream.poll_read(&mut buf) {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(0)) => {
                    // see RETURN VALUE section of recv man page (Unix)
                    debug!(
                        self.logger,
                        "Stream {} has shut down (0-byte read)",
                        Self::stringify(self.local_addr, self.peer_addr)
                    );
                    self.shutdown();
                    return Ok(Async::Ready(()));
                }
                Ok(Async::Ready(length)) => {
                    debug!(
                        self.logger,
                        "Read {}-byte chunk from stream {}",
                        length,
                        Self::stringify(self.local_addr, self.peer_addr)
                    );
                    self.wrangle_discriminators(&buf, length)
                }
                Err(e) => {
                    if indicates_dead_stream(e.kind()) {
                        debug!(
                            self.logger,
                            "Stream {} is dead: {}",
                            Self::stringify(self.local_addr, self.peer_addr),
                            e
                        );
                        self.shutdown();
                        return Err(());
                    } else {
                        // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                        warning!(
                            self.logger,
                            "Continuing after read error on stream {}: {}",
                            Self::stringify(self.local_addr, self.peer_addr),
                            e.to_string()
                        )
                    }
                }
            }
        }
    }
}

impl StreamReaderReal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream: Box<dyn ReadHalfWrapper>,
        reception_port: Option<u16>,
        ibcd_sub: Recipient<dispatcher::InboundClientData>,
        remove_sub: Recipient<RemoveStreamMsg>,
        dispatcher_sub: Recipient<StreamShutdownMsg>,
        discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
        is_clandestine: bool,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> StreamReaderReal {
        let name = format!("StreamReader for {}", peer_addr);
        if discriminator_factories.is_empty() {
            panic!("Internal error: no Discriminator factories!")
        }
        let discriminators: Vec<Discriminator> = discriminator_factories
            .into_iter()
            .map(|df| (df.make()))
            .collect();
        StreamReaderReal {
            stream,
            local_addr,
            peer_addr,
            reception_port,
            ibcd_sub,
            remove_sub,
            dispatcher_stream_shutdown_sub: dispatcher_sub,
            discriminators,
            is_clandestine,
            logger: Logger::new(&name),
            sequencer: Sequencer::new(),
        }
    }

    fn wrangle_discriminators(&mut self, buf: &[u8], length: usize) {
        // Although discriminators is a vec, it was never really designed to have more than one.
        let is_connect = HttpProtocolPack::is_connect(buf);
        let chosen_discriminator = if self.discriminators.len() > 1 && is_connect {
            &mut self.discriminators[1]
        } else {
            &mut self.discriminators[0]
        };

        debug!(self.logger, "Adding {} bytes to discriminator", length);
        chosen_discriminator.add_data(&buf[..length]);
        loop {
            match chosen_discriminator.take_chunk() {
                Some(unmasked_chunk) => {
                    // For Proxy Clients that send an Http Connect message via TLS, sequence_number
                    // should be Some(0). The next message the ProxyClient will send begins the TLS
                    // handshake and should start the sequence at Some(0) as well, the ProxyServer will
                    // handle the sequenced packet offset before sending them through the stream_writer
                    // and avoid dropping duplicate packets.
                    let sequence_number = if unmasked_chunk.sequenced && !is_connect {
                        Some(self.sequencer.next_sequence_number())
                    } else if is_connect {
                        // This case needs to explicitly be Some(0) instead of None so that the StreamHandlerPool does
                        // not masquerade it.
                        Some(0)
                    } else {
                        None
                    };
                    match sequence_number {
                        Some(num) => debug!(
                            self.logger,
                            "Read {} bytes of clear data (#{})",
                            unmasked_chunk.chunk.len(),
                            num
                        ),
                        None => debug!(
                            self.logger,
                            "Read {} bytes of clandestine data",
                            unmasked_chunk.chunk.len()
                        ),
                    };
                    let msg = dispatcher::InboundClientData {
                        timestamp: SystemTime::now(),
                        peer_addr: self.peer_addr,
                        reception_port: self.reception_port,
                        last_data: false,
                        is_clandestine: self.is_clandestine,
                        sequence_number,
                        data: unmasked_chunk.chunk.clone(),
                    };
                    debug!(self.logger, "Discriminator framed and unmasked {} bytes for {}; transmitting via Hopper",
                                              unmasked_chunk.chunk.len(), msg.peer_addr);
                    self.ibcd_sub.try_send(msg).expect("Dispatcher is dead");
                }
                None => {
                    debug!(self.logger, "Discriminator has no more data framed");
                    break;
                }
            }
        }
    }

    fn shutdown(&mut self) {
        debug!(self.logger, "Directing removal of {}clandestine StreamReader with reception_port {:?} on {} listening to {}", if self.is_clandestine {""} else {"non-"}, self.reception_port, self.local_addr, self.peer_addr);
        self.remove_sub
            .try_send(RemoveStreamMsg {
                peer_addr: self.peer_addr,
                local_addr: self.local_addr,
                stream_type: if self.is_clandestine {
                    RemovedStreamType::Clandestine
                } else {
                    RemovedStreamType::NonClandestine(NonClandestineAttributes {
                        reception_port: self.reception_port.expect(
                            "Non-clandestine StreamReader should always have a reception_port",
                        ),
                        sequence_number: self.sequencer.next_sequence_number(),
                    })
                },
                dispatcher_sub: self.dispatcher_stream_shutdown_sub.clone(),
            })
            .expect("StreamHandlerPool is dead");
    }

    fn stringify(local_addr: SocketAddr, peer_addr: SocketAddr) -> String {
        format!("between local {} and peer {}", local_addr, peer_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
    use crate::json_discriminator_factory::JsonDiscriminatorFactory;
    use crate::json_masquerader::JsonMasquerader;
    use crate::masquerader::Masquerader;
    use crate::node_test_utils::{check_timestamp, make_stream_handler_pool_subs_from_recorder};
    use crate::stream_handler_pool::StreamHandlerPoolSubs;
    use crate::stream_messages::RemovedStreamType::NonClandestine;
    use crate::sub_lib::dispatcher::DispatcherSubs;
    use crate::test_utils::recorder::make_dispatcher_subs_from_recorder;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
    use actix::Actor;
    use actix::Addr;
    use actix::System;
    use masq_lib::constants::HTTP_PORT;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::io;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    fn stream_handler_pool_stuff() -> (Arc<Mutex<Recording>>, StreamHandlerPoolSubs) {
        let (shp, _, recording) = make_recorder();
        (
            recording,
            make_stream_handler_pool_subs_from_recorder(&shp.start()),
        )
    }

    fn dispatcher_stuff() -> (Arc<Mutex<Recording>>, DispatcherSubs) {
        let (dispatcher, _, recording) = make_recorder();
        let addr: Addr<Recorder> = dispatcher.start();
        (recording, make_dispatcher_subs_from_recorder(&addr))
    }

    #[test]
    fn stream_reader_shuts_down_and_returns_ok_on_0_byte_read() {
        init_test_logging();
        let system = System::new("test");
        let (shp_recording_arc, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (_, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Ok(Async::Ready(0)))],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            None,
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub.clone(),
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let result = subject.poll();

        System::current().stop_with_code(0);
        system.run();

        let shp_recording = shp_recording_arc.lock().unwrap();
        assert_eq!(
            shp_recording.get_record::<RemoveStreamMsg>(0),
            &RemoveStreamMsg {
                peer_addr,
                local_addr,
                stream_type: RemovedStreamType::Clandestine,
                dispatcher_sub: dispatcher_subs.stream_shutdown_sub,
            }
        );

        assert_eq!(result, Ok(Async::Ready(())));

        TestLogHandler::new().exists_log_containing(
            "DEBUG: StreamReader for 1.2.3.4:5678: Stream between local 1.2.3.5:6789 and peer 1.2.3.4:5678 has shut down (0-byte read)",
        );
    }

    #[test]
    fn stream_reader_shuts_down_and_returns_err_when_it_gets_a_dead_stream_error() {
        init_test_logging();
        let system = System::new("test");
        let (shp_recording_arc, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (_, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Err(io::Error::from(ErrorKind::BrokenPipe)))],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            None,
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub.clone(),
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let result = subject.poll();

        System::current().stop_with_code(0);
        system.run();

        let shp_recording = shp_recording_arc.lock().unwrap();
        assert_eq!(
            shp_recording.get_record::<RemoveStreamMsg>(0),
            &RemoveStreamMsg {
                peer_addr,
                local_addr,
                stream_type: RemovedStreamType::Clandestine,
                dispatcher_sub: dispatcher_subs.stream_shutdown_sub,
            }
        );

        assert_eq!(result, Err(()));

        TestLogHandler::new().exists_log_containing(
            "DEBUG: StreamReader for 1.2.3.4:5678: Stream between local 1.2.3.5:6789 and peer 1.2.3.4:5678 is dead: broken pipe",
        );
    }

    #[test]
    fn stream_reader_returns_not_ready_when_it_gets_not_ready() {
        init_test_logging();
        let system = System::new("test");
        let (shp_recording_arc, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Ok(Async::NotReady))],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let result = subject.poll();

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(result, Ok(Async::NotReady));

        let shp_recording = shp_recording_arc.lock().unwrap();
        assert_eq!(shp_recording.len(), 0);

        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(d_recording.len(), 0);
    }

    #[test]
    fn stream_reader_logs_err_but_does_not_shut_down_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let system = System::new("test");
        let (shp_recording_arc, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![
                (vec![], Err(io::Error::from(ErrorKind::Other))),
                (vec![], Ok(Async::NotReady)),
            ],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let _result = subject.poll();

        System::current().stop_with_code(0);
        system.run();

        TestLogHandler::new().await_log_containing("WARN: StreamReader for 1.2.3.4:5678: Continuing after read error on stream between local 1.2.3.5:6789 and peer 1.2.3.4:5678: other error", 1000);

        let shp_recording = shp_recording_arc.lock().unwrap();
        assert_eq!(shp_recording.len(), 0);

        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(d_recording.len(), 0);
    }

    #[test]
    #[should_panic(expected = "Internal error: no Discriminator factories!")]
    fn stream_reader_panics_with_no_discriminator_factories() {
        init_test_logging();
        let _system = System::new("test");
        let (_, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (_d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> = vec![];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Ok(Async::Ready(5)))],
        };

        let _subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );
    }

    #[test]
    fn stream_reader_sends_framed_chunks_to_dispatcher() {
        init_test_logging();
        let system = System::new("test");
        let (_, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let partial_request = Vec::from("GET http://her".as_bytes());
        let remaining_request = Vec::from("e.com HTTP/1.1\r\n\r\n".as_bytes());
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![
                (
                    partial_request.clone(),
                    Ok(Async::Ready(partial_request.len())),
                ),
                (
                    remaining_request.clone(),
                    Ok(Async::Ready(remaining_request.len())),
                ),
                (vec![], Ok(Async::NotReady)),
            ],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );
        let before = SystemTime::now();

        subject.poll().err();

        System::current().stop_with_code(0);
        system.run();

        let after = SystemTime::now();
        let d_recording = d_recording_arc.lock().unwrap();
        let d_record = d_recording.get_record::<dispatcher::InboundClientData>(0);
        check_timestamp(before, d_record.timestamp, after);
        assert_eq!(
            d_record,
            &dispatcher::InboundClientData {
                timestamp: d_record.timestamp,
                peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: true,
                sequence_number: Some(0),
                data: Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );

        TestLogHandler::new().exists_log_containing(
            "DEBUG: StreamReader for 1.2.3.4:5678: Read 14-byte chunk from stream between local 1.2.3.5:6789 and peer 1.2.3.4:5678",
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: StreamReader for 1.2.3.4:5678: Read 18-byte chunk from stream between local 1.2.3.5:6789 and peer 1.2.3.4:5678",
        );
    }

    #[test]
    fn stream_reader_sends_two_correct_sequenced_messages_when_sent_a_http_connect() {
        let system = System::new("test");
        let (_, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> = vec![
            Box::new(TlsDiscriminatorFactory::new()),
            Box::new(HttpRequestDiscriminatorFactory::new()),
        ];
        let http_connect_request = Vec::from("CONNECT example.com:443 HTTP/1.1\r\n\r\n".as_bytes());
        // Magic TLS Sauce stolen from Configuration
        let tls_request = Vec::from(&[0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03][..]);
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![
                (
                    http_connect_request.clone(),
                    Ok(Async::Ready(http_connect_request.len())),
                ),
                (tls_request.clone(), Ok(Async::Ready(tls_request.len()))),
                (vec![], Ok(Async::NotReady)),
            ],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            false,
            peer_addr,
            local_addr,
        );

        subject.poll().err();

        System::current().stop();
        system.run();

        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(
            Some(0),
            d_recording
                .get_record::<dispatcher::InboundClientData>(0)
                .sequence_number,
        );
        assert_eq!(
            Some(0),
            d_recording
                .get_record::<dispatcher::InboundClientData>(1)
                .sequence_number,
        );
    }

    #[test]
    fn stream_reader_assigns_a_sequence_to_inbound_client_data_that_are_flagged_as_sequenced() {
        let system = System::new("test");
        let (_, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let request1 = Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes());
        let request2 = Vec::from("GET http://example.com HTTP/1.1\r\n\r\n".as_bytes());
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![
                (request1.clone(), Ok(Async::Ready(request1.len()))),
                (vec![], Ok(Async::NotReady)),
                (request2.clone(), Ok(Async::Ready(request2.len()))),
                (vec![], Ok(Async::NotReady)),
            ],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            false,
            peer_addr,
            local_addr,
        );
        let before = SystemTime::now();

        let _result = subject.poll();
        let _result = subject.poll();

        System::current().stop_with_code(0);
        system.run();

        let after = SystemTime::now();
        let d_recording = d_recording_arc.lock().unwrap();
        let d_record = d_recording.get_record::<dispatcher::InboundClientData>(0);
        check_timestamp(before, d_record.timestamp, after);
        assert_eq!(
            d_record,
            &dispatcher::InboundClientData {
                timestamp: d_record.timestamp,
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: false,
                sequence_number: Some(0),
                data: Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );

        let d_record = d_recording.get_record::<dispatcher::InboundClientData>(1);
        check_timestamp(before, d_record.timestamp, after);
        assert_eq!(
            d_record,
            &dispatcher::InboundClientData {
                timestamp: d_record.timestamp,
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: false,
                sequence_number: Some(1),
                data: Vec::from("GET http://example.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );
    }

    #[test]
    fn stream_reader_does_not_assign_sequence_to_inbound_client_data_that_is_not_marked_as_sequence(
    ) {
        let system = System::new("test");
        let (_, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(JsonDiscriminatorFactory::new())];
        let json_masquerader = JsonMasquerader::new();
        let request = Vec::from(
            json_masquerader
                .mask("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes())
                .unwrap(),
        );
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![
                (request.clone(), Ok(Async::Ready(request.len()))),
                (vec![], Ok(Async::NotReady)),
            ],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );
        let before = SystemTime::now();

        let _result = subject.poll();

        System::current().stop_with_code(0);
        system.run();

        let after = SystemTime::now();
        let d_recording = d_recording_arc.lock().unwrap();
        let d_record = d_recording.get_record::<dispatcher::InboundClientData>(0);
        check_timestamp(before, d_record.timestamp, after);
        assert_eq!(
            d_record,
            &dispatcher::InboundClientData {
                timestamp: d_record.timestamp,
                peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: true,
                sequence_number: None,
                data: Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );
    }

    #[test]
    fn shutdown_produces_the_correct_stream_shutdown_msg_for_clandestine_reader() {
        let (shp_recording_arc, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (_, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let system = System::new("test");
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(JsonDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::Ready(0)));
        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            None,
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub.clone(),
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        subject.shutdown();

        System::current().stop_with_code(0);
        system.run();
        let shp_recording = shp_recording_arc.lock().unwrap();
        let remove_stream_msg = shp_recording.get_record::<RemoveStreamMsg>(0);
        assert_eq!(
            remove_stream_msg,
            &RemoveStreamMsg {
                peer_addr,
                local_addr,
                stream_type: RemovedStreamType::Clandestine,
                dispatcher_sub: dispatcher_subs.stream_shutdown_sub,
            }
        );
    }

    #[test]
    fn shutdown_produces_the_correct_stream_shutdown_msg_for_non_clandestine_reader() {
        let (shp_recording_arc, stream_handler_pool_subs) = stream_handler_pool_stuff();
        let (_, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let system = System::new("test");
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<dyn DiscriminatorFactory>> =
            vec![Box::new(JsonDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock::new().poll_read_result(vec![], Ok(Async::Ready(0)));
        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(HTTP_PORT),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            dispatcher_subs.stream_shutdown_sub.clone(),
            discriminator_factories,
            false,
            peer_addr,
            local_addr,
        );
        subject.sequencer.next_sequence_number(); // just so it's not 0

        subject.shutdown();

        System::current().stop_with_code(0);
        system.run();
        let shp_recording = shp_recording_arc.lock().unwrap();
        let remove_stream_msg = shp_recording.get_record::<RemoveStreamMsg>(0);
        assert_eq!(
            remove_stream_msg,
            &RemoveStreamMsg {
                peer_addr,
                local_addr,
                stream_type: NonClandestine(NonClandestineAttributes {
                    reception_port: HTTP_PORT,
                    sequence_number: 1,
                }),
                dispatcher_sub: dispatcher_subs.stream_shutdown_sub,
            }
        );
    }
}
