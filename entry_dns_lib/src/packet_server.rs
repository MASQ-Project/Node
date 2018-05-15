// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
use sub_lib::logger::Logger;
use processor::ProcessorTrait;

pub trait PacketServerTrait {
    fn serve (&mut self, buf: &mut [u8]);
}

pub struct PacketServerReal<'a, S: 'a, P: 'a> where S: UdpSocketWrapperTrait, P: ProcessorTrait {
    pub logger: Logger,
    pub socket: &'a S,
    pub processor: &'a P
}

impl<'a, S: UdpSocketWrapperTrait, P: ProcessorTrait> PacketServerTrait for PacketServerReal<'a, S, P> {
    fn serve (&mut self, mut buf: &mut [u8]) {
        let recv_result = self.socket.recv_from (&mut buf);
        let (request_length, addr) = match recv_result {
            Ok (size_and_address) => size_and_address,
            Err (e) => {self.logger.error(format! ("Couldn't receive packet: {}", e)); return}
        };
        let response_length = self.processor.process (buf, request_length, &addr, &self.logger);
        match self.socket.send_to (&buf[0..response_length], addr) {
            Ok (_) => (),
            Err (e) => self.logger.error(format! ("Couldn't respond: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
    use std::io;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::net::IpAddr;
    use std::cell::RefCell;
    use std::time::Duration;
    use test_utils::test_utils::TestLogHandler;
    use test_utils::test_utils::init_test_logging;
    use processor::ProcessorTrait;

    struct UdpSocketWrapperMock {
        bind_result: RefCell<Vec<io::Result<bool>>>,
        recv_from_results: RefCell<Vec<io::Result<(usize, SocketAddr)>>>,
        send_to_results: RefCell<Vec<io::Result<usize>>>,
        call_log: RefCell<Vec<String>>
    }

    impl UdpSocketWrapperTrait for UdpSocketWrapperMock {
        fn bind (&mut self, addr: SocketAddr) -> io::Result<bool> {
            self.call_log.borrow_mut ().push (String::from (format! ("bind ({:?})", addr)));
            self.bind_result.borrow_mut ().pop ().unwrap ()
        }

        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            unimplemented!()
        }

        fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.call_log.borrow_mut ().push (String::from (format! ("recv_from ({:?})", buf)));
            self.recv_from_results.borrow_mut ().pop ().unwrap ()
        }

        fn send_to (&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.call_log.borrow_mut ().push (String::from (format! ("send_to ({:?}, {:?})", buf, addr)));
            self.send_to_results.borrow_mut ().pop ().unwrap ()
        }
    }

    impl UdpSocketWrapperMock {
        fn new (bind_result: io::Result<bool>, mut recv_from_results: Vec<io::Result<(usize, SocketAddr)>>,
                mut send_to_results: Vec<io::Result<usize>>) -> UdpSocketWrapperMock {
            recv_from_results.reverse ();
            send_to_results.reverse ();
            UdpSocketWrapperMock {
                bind_result: RefCell::new (vec![bind_result]),
                recv_from_results: RefCell::new (recv_from_results),
                send_to_results: RefCell::new (send_to_results),
                call_log: RefCell::new (Vec::new ())
            }
        }
    }

    struct ProcessorMock {
        process_results: RefCell<Vec<usize>>,
        call_log: RefCell<Vec<String>>
    }

    impl ProcessorTrait for ProcessorMock {
        fn process (&self, buf: &mut[u8], length: usize, addr: &SocketAddr, logger: &Logger) -> usize {
            self.call_log.borrow_mut ().push (String::from (format! ("process ({:?}, {}, {:?}, streams)",
                buf, length, addr)));
            logger.info(String::from("processed"));
            self.process_results.borrow_mut ().pop ().unwrap ()
        }
    }

    impl ProcessorMock {
        fn new (mut process_results: Vec<usize>) -> ProcessorMock {
            process_results.reverse ();
            ProcessorMock {
                process_results: RefCell::new (process_results),
                call_log: RefCell::new (Vec::new ())
            }
        }
    }

    #[test]
    pub fn complains_when_packet_cant_be_received () {
        init_test_logging();
        let mut socket = UdpSocketWrapperMock::new (
            Ok (true),
            vec![Err (Error::from (ErrorKind::BrokenPipe))],
            vec![]
        );
        let processor = ProcessorMock::new (vec![]);
        let mut buf = [0; 0];
        let mut subject = PacketServerReal { logger: Logger::new ("EntryDnsServer"), socket: &mut socket, processor: &processor };

        subject.serve(&mut buf);

        let tlh = TestLogHandler::new ();
        tlh.exists_log_containing ("ERROR: EntryDnsServer: Couldn't receive packet: broken pipe");
    }

    #[test]
    pub fn complains_when_packet_cant_be_sent () {
        init_test_logging();
        let mut socket = UdpSocketWrapperMock::new (
            Ok (true),
            vec![Ok((2, SocketAddr::new (IpAddr::from ([1, 2, 3, 4]), 123)))],
            vec![Err (Error::from (ErrorKind::BrokenPipe))]
        );
        let processor = ProcessorMock::new (vec![3]);
        {
            let mut buf = [0; 4];
            let mut subject = PacketServerReal { logger: Logger::new ("complains_when_packet_cant_be_sent"), socket: &mut socket, processor: &processor };

            subject.serve(&mut buf);
        };

        let actual = processor.call_log;
        let expected = RefCell::new (vec![String::from ("process ([0, 0, 0, 0], 2, V4(1.2.3.4:123), streams)")]);
        assert_eq! (actual, expected);
        let tlh = TestLogHandler::new ();
        tlh.assert_logs_contain_in_order(vec! (
            "INFO: complains_when_packet_cant_be_sent: processed",
            "ERROR: complains_when_packet_cant_be_sent: Couldn't respond: broken pipe"
        ));
    }

    #[test]
    pub fn succeeds_when_everything_is_copacetic () {
        init_test_logging();
        let mut socket = UdpSocketWrapperMock::new (
            Ok (true),
            vec![Ok ((2, SocketAddr::new (IpAddr::from ([1, 2, 3, 4]), 123)))],
            vec![Ok (3)]
        );
        let processor = ProcessorMock::new (vec![3]);
        {
            let mut buf = [0; 4];
            let mut subject = PacketServerReal { logger: Logger::new ("EntryDnsServer"), socket: &mut socket, processor: &processor };

            subject.serve(&mut buf);
        };

        let actual = processor.call_log;
        let expected = RefCell::new (vec![String::from ("process ([0, 0, 0, 0], 2, V4(1.2.3.4:123), streams)")]);
        assert_eq! (actual, expected);
        let tlh = TestLogHandler::new ();
        tlh.exists_log_containing ("INFO: EntryDnsServer: processed");
    }
}
