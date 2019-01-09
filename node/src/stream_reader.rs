// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;
use std::net::SocketAddr;
use stream_messages::*;
use sub_lib::dispatcher;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::logger::Logger;
use sub_lib::sequencer::Sequencer;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::utils::indicates_dead_stream;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct StreamReaderReal {
    stream: Box<ReadHalfWrapper>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    reception_port: Option<u16>,
    ibcd_sub: Recipient<Syn, dispatcher::InboundClientData>,
    remove_sub: Recipient<Syn, RemoveStreamMsg>,
    discriminators: Vec<Discriminator>,
    is_clandestine: bool,
    logger: Logger,
    sequencer: Sequencer,
}

impl Future for StreamReaderReal {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<()>, ()> {
        let port = self.local_addr.port();
        let mut buf = [0u8; 0x10000];
        loop {
            match self.stream.poll_read(&mut buf) {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(0)) => {
                    // see RETURN VALUE section of recv man page (Unix)
                    self.logger.debug(format!(
                        "Stream on port {} has shut down (0-byte read)",
                        port
                    ));
                    self.shutdown();
                    return Ok(Async::Ready(()));
                }
                Ok(Async::Ready(length)) => {
                    self.logger
                        .debug(format!("Read {}-byte chunk from port {}", length, port));
                    self.wrangle_discriminators(&buf, length)
                }
                Err(e) => {
                    if indicates_dead_stream(e.kind()) {
                        self.logger
                            .debug(format!("Stream on port {} is dead: {}", port, e));
                        self.shutdown();
                        return Err(());
                    } else {
                        // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                        self.logger.warning(format!(
                            "Continuing after read error on port {}: {}",
                            port,
                            e.to_string()
                        ))
                    }
                }
            }
        }
    }
}

impl StreamReaderReal {
    pub fn new(
        stream: Box<ReadHalfWrapper>,
        reception_port: Option<u16>,
        ibcd_sub: Recipient<Syn, dispatcher::InboundClientData>,
        remove_sub: Recipient<Syn, RemoveStreamMsg>,
        discriminator_factories: Vec<Box<DiscriminatorFactory>>,
        is_clandestine: bool,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> StreamReaderReal {
        let name = format!("StreamReader for {}", peer_addr);
        if discriminator_factories.is_empty() {
            panic!("Internal error: no Discriminator factories!")
        }
        StreamReaderReal {
            stream,
            local_addr,
            peer_addr,
            reception_port,
            ibcd_sub,
            remove_sub,
            // Skinny implementation
            discriminators: vec![discriminator_factories[0].make()],
            is_clandestine,
            logger: Logger::new(&name),
            sequencer: Sequencer::new(),
        }
    }

    fn wrangle_discriminators(&mut self, buf: &[u8], length: usize) {
        // Skinny implementation
        self.logger
            .debug(format!("Adding {} bytes to discriminator", length));
        self.discriminators[0].add_data(&buf[..length]);
        loop {
            match self.discriminators[0].take_chunk() {
                Some(unmasked_chunk) => {
                    let sequence_number = if unmasked_chunk.sequenced {
                        Some(self.sequencer.next_sequence_number())
                    } else {
                        None
                    };
                    match sequence_number {
                        Some(num) => self.logger.debug(format!(
                            "Read {} bytes of clear data (#{})",
                            unmasked_chunk.chunk.len(),
                            num
                        )),
                        None => self.logger.debug(format!(
                            "Read {} bytes of clandestine data",
                            unmasked_chunk.chunk.len()
                        )),
                    };
                    let msg = dispatcher::InboundClientData {
                        peer_addr: self.peer_addr,
                        reception_port: self.reception_port,
                        last_data: false,
                        is_clandestine: self.is_clandestine,
                        sequence_number,
                        data: unmasked_chunk.chunk.clone(),
                    };
                    self.logger.debug (format! ("Discriminator framed and unmasked {} bytes for {}; transmitting via Hopper",
                                                 unmasked_chunk.chunk.len (), msg.peer_addr));
                    self.ibcd_sub.try_send(msg).expect("Dispatcher is dead");
                }
                None => {
                    self.logger
                        .debug(format!("Discriminator has no more data framed"));
                    break;
                }
            }
        }
    }

    fn shutdown(&mut self) {
        self.remove_sub
            .try_send(RemoveStreamMsg {
                socket_addr: self.peer_addr,
            })
            .expect("StreamHandlerPool is dead");
        // TODO: Skinny implementation: wrong for decentralization. StreamReaders for clandestine and non-clandestine data should probably behave differently here.
        let sequence_number = Some(self.sequencer.next_sequence_number());
        self.ibcd_sub
            .try_send(InboundClientData {
                peer_addr: self.peer_addr,
                reception_port: self.reception_port,
                last_data: true,
                is_clandestine: self.is_clandestine,
                sequence_number,
                data: Vec::new(),
            })
            .expect("Dispatcher is dead");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Actor;
    use actix::Addr;
    use actix::Arbiter;
    use actix::System;
    use http_request_start_finder::HttpRequestDiscriminatorFactory;
    use json_discriminator_factory::JsonDiscriminatorFactory;
    use json_masquerader::JsonMasquerader;
    use masquerader::Masquerader;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use std::io;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use stream_handler_pool::StreamHandlerPoolSubs;
    use sub_lib::dispatcher::DispatcherSubs;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_dispatcher_subs_from;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::RecordAwaiter;
    use test_utils::recorder::Recorder;
    use test_utils::recorder::Recording;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;

    fn stream_handler_pool_stuff() -> (RecordAwaiter, Arc<Mutex<Recording>>, StreamHandlerPoolSubs)
    {
        let (shp, awaiter, recording) = make_recorder();
        (
            awaiter,
            recording,
            make_stream_handler_pool_subs_from(Some(shp)),
        )
    }

    fn dispatcher_stuff() -> (RecordAwaiter, Arc<Mutex<Recording>>, DispatcherSubs) {
        let (dispatcher, awaiter, recording) = make_recorder();
        let addr: Addr<Syn, Recorder> = dispatcher.start();
        (awaiter, recording, make_dispatcher_subs_from(&addr))
    }

    #[test]
    fn stream_reader_shuts_down_and_returns_ok_on_0_byte_read() {
        init_test_logging();
        let system = System::new("test");
        let (shp_awaiter, shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Ok(Async::Ready(0)))],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        shp_awaiter.await_message_count(1);
        let shp_recording = shp_recording_arc.lock().unwrap();
        assert_eq!(
            shp_recording.get_record::<RemoveStreamMsg>(0),
            &RemoveStreamMsg {
                socket_addr: peer_addr
            }
        );

        d_awaiter.await_message_count(1);
        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(
            d_recording.get_record::<dispatcher::InboundClientData>(0),
            &dispatcher::InboundClientData {
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: true,
                is_clandestine: true,
                sequence_number: Some(0),
                data: Vec::new(),
            }
        );

        assert_eq!(result, Ok(Async::Ready(())));

        TestLogHandler::new ().exists_log_matching("ThreadId\\(\\d+\\): DEBUG: StreamReader for 1\\.2\\.3\\.4:5678: Stream on port 6789 has shut down \\(0-byte read\\)");
    }

    #[test]
    fn stream_reader_shuts_down_and_returns_err_when_it_gets_a_dead_stream_error() {
        init_test_logging();
        let system = System::new("test");
        let (shp_awaiter, shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Err(io::Error::from(ErrorKind::BrokenPipe)))],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        shp_awaiter.await_message_count(1);
        let shp_recording = shp_recording_arc.lock().unwrap();
        assert_eq!(
            shp_recording.get_record::<RemoveStreamMsg>(0),
            &RemoveStreamMsg {
                socket_addr: peer_addr
            }
        );

        d_awaiter.await_message_count(1);
        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(
            d_recording.get_record::<dispatcher::InboundClientData>(0),
            &dispatcher::InboundClientData {
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: true,
                is_clandestine: true,
                sequence_number: Some(0),
                data: Vec::new(),
            }
        );

        assert_eq!(result, Err(()));

        TestLogHandler::new ().exists_log_matching("ThreadId\\(\\d+\\): DEBUG: StreamReader for 1\\.2\\.3\\.4:5678: Stream on port 6789 is dead: broken pipe");
    }

    #[test]
    fn stream_reader_returns_not_ready_when_it_gets_not_ready() {
        init_test_logging();
        let system = System::new("test");
        let (_shp_awaiter, shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (_d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
            vec![Box::new(HttpRequestDiscriminatorFactory::new())];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Ok(Async::NotReady))],
        };

        let mut subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
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
        let (_shp_awaiter, shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (_d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
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
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let _result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        TestLogHandler::new ().await_log_matching("ThreadId\\(\\d+\\): WARN: StreamReader for 1\\.2\\.3\\.4:5678: Continuing after read error on port 6789: other os error", 1000);

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
        let (_shp_awaiter, _shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (_d_awaiter, _d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> = vec![];
        let reader = ReadHalfWrapperMock {
            poll_read_results: vec![(vec![], Ok(Async::Ready(5)))],
        };

        let _subject = StreamReaderReal::new(
            Box::new(reader),
            Some(1234 as u16),
            dispatcher_subs.ibcd_sub,
            stream_handler_pool_subs.remove_sub,
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
        let (_shp_awaiter, _shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
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
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        subject.poll().err();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        d_awaiter.await_message_count(1);
        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(
            d_recording.get_record::<dispatcher::InboundClientData>(0),
            &dispatcher::InboundClientData {
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: true,
                sequence_number: Some(0),
                data: Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );

        TestLogHandler::new ().exists_log_matching("ThreadId\\(\\d+\\): DEBUG: StreamReader for 1\\.2\\.3\\.4:5678: Read 14-byte chunk from port 6789");
        TestLogHandler::new ().exists_log_matching("ThreadId\\(\\d+\\): DEBUG: StreamReader for 1\\.2\\.3\\.4:5678: Read 18-byte chunk from port 6789");
    }

    #[test]
    fn stream_reader_assigns_a_sequence_to_inbound_client_data_that_are_flagged_as_sequenced() {
        let system = System::new("test");
        let (_shp_awaiter, _shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
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
            discriminator_factories,
            false,
            peer_addr,
            local_addr,
        );

        let _result = subject.poll();
        let _result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        d_awaiter.await_message_count(2);
        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(
            d_recording.get_record::<dispatcher::InboundClientData>(0),
            &dispatcher::InboundClientData {
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: false,
                sequence_number: Some(0),
                data: Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );

        assert_eq!(
            d_recording.get_record::<dispatcher::InboundClientData>(1),
            &dispatcher::InboundClientData {
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
    fn stream_reader_does_not_assign_sequence_to_inbound_client_data_that_is_not_marked_as_sequenece(
    ) {
        let system = System::new("test");
        let (_shp_awaiter, _shp_recording_arc, stream_handler_pool_subs) =
            stream_handler_pool_stuff();
        let (d_awaiter, d_recording_arc, dispatcher_subs) = dispatcher_stuff();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let discriminator_factories: Vec<Box<DiscriminatorFactory>> =
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
            discriminator_factories,
            true,
            peer_addr,
            local_addr,
        );

        let _result = subject.poll();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        d_awaiter.await_message_count(1);
        let d_recording = d_recording_arc.lock().unwrap();
        assert_eq!(
            d_recording.get_record::<dispatcher::InboundClientData>(0),
            &dispatcher::InboundClientData {
                peer_addr: peer_addr,
                reception_port: Some(1234 as u16),
                last_data: false,
                is_clandestine: true,
                sequence_number: None,
                data: Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes()),
            }
        );
    }
}
