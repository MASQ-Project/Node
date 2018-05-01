// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::time::Instant;
use std::net::SocketAddr;
use std::net::IpAddr;
use sub_lib::packet_facade::PacketFacade;
use sub_lib::packet_facade::Query;
use sub_lib::packet_facade::ResourceRecord;
use sub_lib::logger::Logger;

pub trait ProcessorTrait {
    fn process (&self, buf: &mut[u8], length: usize, addr: &SocketAddr, logger: &Logger) -> usize;
}

pub struct ProcessorReal {
    target_ip: IpAddr
}

impl ProcessorReal {
    pub fn new (target_ip: IpAddr) -> ProcessorReal {
        ProcessorReal {target_ip}
    }
}

impl ProcessorTrait for ProcessorReal {
    fn process (&self, buf: &mut [u8], length: usize, addr: &SocketAddr, logger: &Logger) -> usize {
        let mut facade = PacketFacade::new(buf, length);
        let request_record = RequestRecord {
            timestamp: Instant::now (),
            opcode: facade.get_opcode ().unwrap_or (0xFF),
            queries: facade.get_queries ().unwrap_or (vec![])
        };
        let result: usize;
        loop {
            if facade.get_opcode().expect("The provided buffer must have more than 0 bytes") != 0x0 {
                result = ProcessorReal::make_not_implemented_error(&mut facade);
                break;
            }
            let success =
                facade.set_query(false) &&
                facade.set_authoritative_answer(false) &&
                facade.set_truncated(false) &&
                facade.set_recursion_available(true) &&
                facade.set_authenticated_data(false) &&
                facade.set_checking_disabled(false);
            if !success { result = ProcessorReal::make_format_error(&mut facade); break };
            let queries = match facade.get_queries() {
                None => {result = ProcessorReal::make_format_error(&mut facade); break },
                Some(q) => q
            };
            for query in queries {
                if query.get_query_type() != 0x0001 { return ProcessorReal::make_not_implemented_error(&mut facade) }
                if query.get_query_class() != 0x0001 { return ProcessorReal::make_not_implemented_error(&mut facade) }
                let octets = match self.target_ip {
                    IpAddr::V4 (ipv4) => ipv4.octets (),
                    // crashpoint - make a card
                    IpAddr::V6 (_ipv6) => unimplemented!()
                };
                facade.add_answer(&query.get_query_name(), 0x0001, 0x0001, 3600, &octets);
            }

            result = facade.get_length();
            break;
        }
        let latency = request_record.timestamp.elapsed ();
        let response_record = ResponseRecord {
            latency_ns: ((latency.as_secs () as u64) * 1000000000) + (latency.subsec_nanos() as u64),
            rcode: facade.get_rcode ().unwrap_or (0xFF),
            answers: facade.get_answers ().unwrap_or (vec![])
        };
        ProcessorReal::write_log (&request_record, &response_record, addr, logger);
        return result;
    }
}

impl ProcessorReal {
    fn make_format_error (facade: &mut PacketFacade) -> usize {
        facade.set_query (false);
        facade.set_authoritative_answer (false);
        facade.set_truncated (false);
        facade.set_recursion_available (true);
        facade.set_authenticated_data (false);
        facade.set_checking_disabled (false);
        facade.set_rcode (0x1);
        facade.clear();
        return 12
    }

    fn make_not_implemented_error (facade: &mut PacketFacade) -> usize {
        facade.set_query (false);
        facade.set_authoritative_answer (false);
        facade.set_truncated (false);
        facade.set_recursion_available (true);
        facade.set_authenticated_data (false);
        facade.set_checking_disabled (false);
        facade.set_rcode (0x4);
        facade.clear();
        return 12
    }

    fn write_log (from: &RequestRecord, to: &ResponseRecord, addr: &SocketAddr, logger: &Logger) {
        let mut query_list = String::new ();
        for query in from.queries.as_slice () {
            if !query_list.is_empty () {query_list += ", "}
            query_list += &format! ("{}/{}/{}", query.get_query_type (), query.get_query_class (), query.get_query_name());
        }
        let mut answer_list = String::new ();
        for answer in to.answers.as_slice () {
            if !answer_list.is_empty () {answer_list += ", "}
            let rdata = answer.get_rdata ();
            // TODO: What if there aren't four elements in this array?
            answer_list += &format! ("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        logger.info(format! ("{}ns: {} RQ{:X} ({}) -> RS{:X} ({})",
            to.latency_ns, addr, from.opcode, &query_list, to.rcode, &answer_list));
    }
}

struct RequestRecord {
    timestamp: Instant,
    opcode: u8,
    queries: Vec<Query>
}

struct ResponseRecord {
    latency_ns: u64,
    rcode: u8,
    answers: Vec<ResourceRecord>
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;
    use std::net::Ipv4Addr;
    use std::net::IpAddr;
    use std::str::FromStr;
    use sub_lib::packet_facade::PacketFacade;
    use sub_lib::packet_facade::Query;
    use sub_lib::packet_facade::ResourceRecord;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::TestLogHandler;
    use sub_lib::logger::Logger;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use processor::ProcessorTrait;
    use processor::ProcessorReal;
    use processor::RequestRecord;
    use processor::ResponseRecord;

    #[test]
    fn returns_format_error_if_queries_overrun () {
        let memory: [u8; 100] = [0; 100];
        let mut correct_buf: Vec<u8> = Vec::from (&memory[0..memory.len()]);
        let correct_length = {
            let mut facade = PacketFacade::new (&mut correct_buf, 12);
            facade.set_transaction_id (0x1234);
            facade.set_query (true);
            facade.set_recursion_available (false);
            facade.set_recursion_desired (false);
            facade.set_opcode (0x0);
            facade.add_query ("name", 0x0001, 0x0001);
            facade.get_length ()
        };
        let truncated_length = correct_length - 1;
        let truncated_buf = &mut correct_buf[0..truncated_length];
        let addr = SocketAddr::from (SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        let subject = ProcessorReal::new (IpAddr::from_str ("123.124.125.126").unwrap ());

        let result = subject.process(truncated_buf, truncated_length, &addr,
            &Logger::new (""));

        check_format_error_message(truncated_buf, 0x1234);
        assert_eq! (result, 12);
    }

    #[test]
    fn returns_not_implemented_error_if_opcode_is_other_than_0x0 () {
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut facade = PacketFacade::new(&mut buf, 500);
            facade.set_transaction_id (0x1234);
            facade.set_query (true);
            facade.set_recursion_available (false);
            facade.set_recursion_desired (false);
            facade.set_opcode (0x1);
            facade.add_query ("name", 0x0001, 0x0001);
            facade.get_length ()
        };
        let addr = SocketAddr::from (SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        let subject = ProcessorReal::new (IpAddr::from_str ("18.52.86.120").unwrap ());

        let rsp_length = subject.process (&mut buf, req_length, &addr,
            &Logger::new (""));

        check_not_implemented_error_message (&mut buf, 0x1234, 0x1);
        assert_eq! (rsp_length, 12);
    }

    #[test]
    fn returns_not_implemented_error_if_query_type_is_other_than_0x0001 () {
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut facade = PacketFacade::new(&mut buf, 500);
            facade.set_transaction_id (0x1234);
            facade.set_query (true);
            facade.set_recursion_available (false);
            facade.set_recursion_desired (false);
            facade.set_opcode (0x0);
            facade.add_query ("name", 0x0000, 0x0001);
            facade.get_length ()
        };
        let addr = SocketAddr::from (SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        let subject = ProcessorReal::new (IpAddr::from_str ("18.52.86.120").unwrap ());

        let rsp_length = subject.process (&mut buf, req_length, &addr,
            &Logger::new (""));

        check_not_implemented_error_message (&mut buf, 0x1234, 0x0);
        assert_eq! (rsp_length, 12);
    }

    #[test]
    fn returns_not_implemented_error_if_query_class_is_other_than_0x0001 () {
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut facade = PacketFacade::new(&mut buf, 500);
            facade.set_transaction_id (0x1234);
            facade.set_query (true);
            facade.set_recursion_available (false);
            facade.set_recursion_desired (false);
            facade.set_opcode (0x0);
            facade.add_query ("name", 0x0001, 0x0000);
            facade.get_length ()
        };
        let addr = SocketAddr::from (SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        let subject = ProcessorReal::new (IpAddr::from_str ("18.52.86.120").unwrap ());

        let rsp_length = subject.process (&mut buf, req_length, &addr, &Logger::new (""));

        check_not_implemented_error_message (&mut buf, 0x1234, 0x0);
        assert_eq! (rsp_length, 12);
    }

    #[test]
    fn two_queries_are_answered () {
        LoggerInitializerWrapperMock::new ().init ();
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut request = PacketFacade::new(&mut buf, 500);
            assert_eq! (request.set_transaction_id(0x4321), true);
            assert_eq! (request.set_query(true), true);
            assert_eq! (request.set_truncated(false), true);
            assert_eq! (request.set_recursion_desired(false), true);
            assert_eq! (request.set_checking_disabled(false), true);
            assert_eq! (request.set_opcode(0x0), true);
            assert_eq! (request.add_query("ooga.com", 0x0001, 0x0001), true);
            assert_eq! (request.add_query("booga.com", 0x0001, 0x0001), true);
            request.get_length ()
        };
        let addr = SocketAddr::from (SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        let rsp_length = {
            let subject = ProcessorReal::new (IpAddr::from_str ("18.52.86.120").unwrap ());

            subject.process(&mut buf, req_length, &addr, &Logger::new ("two_queries_are_answered"))
        };

        {
            let response = PacketFacade::new(&mut buf, rsp_length);

            assert_eq!(response.get_transaction_id(), Some (0x4321));
            assert_eq!(response.is_query(), Some (false));
            assert_eq!(response.get_opcode(), Some (0x0));
            assert_eq!(response.is_authoritative_answer(), Some (false));
            assert_eq!(response.is_truncated(), Some (false));
            assert_eq!(response.is_recursion_desired(), Some (false));
            assert_eq!(response.is_recursion_available(), Some (true));
            assert_eq!(response.get_z(), Some (false));
            assert_eq!(response.is_authenticated_data(), Some (false));
            assert_eq!(response.is_checking_disabled(), Some (false));
            assert_eq!(response.get_rcode (), Some (0x0000));
            let queries = response.get_queries().unwrap();
            assert_eq!(queries[0].get_query_name(), "ooga.com");
            assert_eq!(queries[0].get_query_type(), 0x0001);
            assert_eq!(queries[0].get_query_class(), 0x0001);
            assert_eq!(queries[1].get_query_name(), "booga.com");
            assert_eq!(queries[1].get_query_type(), 0x0001);
            assert_eq!(queries[1].get_query_class(), 0x0001);
            assert_eq!(queries.len(), 2);
            let answers = response.get_answers().unwrap();
            assert_eq!(answers[0].get_name(), "ooga.com");
            assert_eq!(answers[0].get_resource_class(), 0x0001);
            assert_eq!(answers[0].get_resource_type(), 0x0001);
            assert_eq!(answers[0].get_time_to_live(), 3600);
            assert_eq!(answers[0].get_rdata(), vec![0x12 as u8, 0x34 as u8, 0x56 as u8, 0x78 as u8].as_slice ());
            assert_eq!(answers[1].get_name(), "booga.com");
            assert_eq!(answers[1].get_resource_class(), 0x0001);
            assert_eq!(answers[1].get_resource_type(), 0x0001);
            assert_eq!(answers[1].get_time_to_live(), 3600);
            assert_eq!(answers[1].get_rdata(), vec![0x12 as u8, 0x34 as u8, 0x56 as u8, 0x78 as u8].as_slice ());
            assert_eq!(answers.len(), 2);
            assert_eq!(response.get_authorities().unwrap().len(), 0);
            assert_eq!(response.get_additionals().unwrap().len(), 0);
        }

        let tlh = TestLogHandler::new ();
        tlh.exists_log_containing ("101.102.103.104:53 RQ0 (1/1/ooga.com, 1/1/booga.com) -> RS0 (18.52.86.120, 18.52.86.120)");
    }

    #[test]
    fn write_log_produces_correct_text () {
        LoggerInitializerWrapperMock::new ().init ();
        let request_record = RequestRecord {
            timestamp: Instant::now (),
            opcode: 0x2,
            queries: vec![
                Query::new_for_test (String::from ("first"), 0x1234, 0x2345, 11),
                Query::new_for_test (String::from ("second"),0x3456, 0x4567, 12)
            ]
        };
        let response_record = ResponseRecord {
            latency_ns: 2345,
            rcode: 0x3,
            answers: vec![
                ResourceRecord::new_for_test (String::from ("first"), 0x1234, 0x2345, 0x34567890,
                                              vec![123, 124, 125, 126], 21),
                ResourceRecord::new_for_test (String::from ("second"), 0x3456, 0x4567, 0x4567890A,
                                              vec![124, 125, 126, 127], 22)
            ]
        };
        let addr = SocketAddr::from (SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        {
            ProcessorReal::write_log(&request_record, &response_record, &addr, &Logger::new("write_log_produces_correct_text"));
        }

        TestLogHandler::new ().exists_log_containing("2345ns: 101.102.103.104:53 RQ2 (4660/9029/first, 13398/17767/second) -> RS3 (123.124.125.126, 124.125.126.127)");
    }

    fn check_format_error_message (mut buf: &mut [u8], transaction_id: u16) {
        let facade = PacketFacade::new (&mut buf, 12);
        assert_eq! (facade.get_transaction_id(), Some (transaction_id));
        assert_eq! (facade.is_query(), Some (false));
        assert_eq! (facade.get_opcode(), Some (0x0));
        assert_eq! (facade.is_authoritative_answer(), Some (false));
        assert_eq! (facade.is_truncated(), Some (false));
        assert_eq! (facade.is_recursion_desired(), Some (false));
        assert_eq! (facade.is_recursion_available(), Some (true));
        assert_eq! (facade.get_z (), Some (false));
        assert_eq! (facade.is_authenticated_data(), Some (false));
        assert_eq! (facade.is_checking_disabled(), Some (false));
        assert_eq! (facade.get_rcode (), Some (0x1));
        assert_eq! (facade.get_queries().unwrap ().len (), 0);
        assert_eq! (facade.get_answers().unwrap ().len (), 0);
        assert_eq! (facade.get_authorities().unwrap ().len (), 0);
        assert_eq! (facade.get_additionals().unwrap ().len (), 0);
        assert_eq! (facade.get_length (), 12);
    }

    fn check_not_implemented_error_message (mut buf: &mut [u8], transaction_id: u16, opcode: u8) {
        let facade = PacketFacade::new (&mut buf, 12);
        assert_eq! (facade.get_transaction_id(), Some (transaction_id));
        assert_eq! (facade.is_query(), Some (false));
        assert_eq! (facade.get_opcode(), Some (opcode));
        assert_eq! (facade.is_authoritative_answer(), Some (false));
        assert_eq! (facade.is_truncated(), Some (false));
        assert_eq! (facade.is_recursion_desired(), Some (false));
        assert_eq! (facade.is_recursion_available(), Some (true));
        assert_eq! (facade.get_z (), Some (false));
        assert_eq! (facade.is_authenticated_data(), Some (false));
        assert_eq! (facade.is_checking_disabled(), Some (false));
        assert_eq! (facade.get_rcode (), Some (0x4));
        assert_eq! (facade.get_queries().unwrap ().len (), 0);
        assert_eq! (facade.get_answers().unwrap ().len (), 0);
        assert_eq! (facade.get_authorities().unwrap ().len (), 0);
        assert_eq! (facade.get_additionals().unwrap ().len (), 0);
        assert_eq! (facade.get_length (), 12);
    }
}
