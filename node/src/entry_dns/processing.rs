// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use super::packet_facade::PacketFacade;
use super::packet_facade::Query;
use super::packet_facade::ResourceRecord;
use hickory_proto::op::ResponseCode;
use hickory_resolver::proto::op::OpCode;
use hickory_resolver::proto::rr::{DNSClass, RecordType};
use masq_lib::logger::Logger;
use std::convert::From;
use std::convert::TryFrom;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

const HEADER_BYTES: usize = 12;
const UNKNOWN: &str = "<unknown>";

pub fn process(buf: &mut [u8], length: usize, addr: &SocketAddr, logger: &Logger) -> usize {
    let mut facade = PacketFacade::new(buf, length);
    let request_record = RequestRecord {
        timestamp: Instant::now(),
        opcode: facade.get_opcode().unwrap_or(0xFF),
        queries: facade.get_queries().unwrap_or_default(),
    };

    let response_size = make_response(&mut facade);

    let latency = request_record.timestamp.elapsed();
    let response_record = ResponseRecord {
        latency_ns: latency.as_nanos() as u64,
        rcode: facade.get_rcode().unwrap_or(0xFF),
        answers: facade.get_answers().unwrap_or_default(),
    };
    write_log(&request_record, &response_record, addr, logger);
    response_size
}

fn make_response(facade: &mut PacketFacade) -> usize {
    match facade.get_opcode() {
        None => return make_format_error(facade),
        Some(opcode) if opcode == u8::from(OpCode::Query) => (),
        Some(_) => return make_not_implemented_error(facade),
    }
    if !(facade.set_query(false)
        && facade.set_authoritative_answer(false)
        && facade.set_truncated(false)
        && facade.set_recursion_available(true)
        && facade.set_authenticated_data(false)
        && facade.set_checking_disabled(false))
    {
        return make_format_error(facade);
    }
    let queries = match facade.get_queries() {
        None => return make_format_error(facade),
        Some(q) => q,
    };
    for query in queries {
        if query.get_query_class() != u16::from(DNSClass::IN) {
            return make_not_implemented_error(facade);
        }

        let resource_type = query.get_query_type();
        match RecordType::from(resource_type) {
            RecordType::A => facade.add_answer(
                query.get_query_name(),
                resource_type,
                DNSClass::IN.into(),
                3600,
                &Ipv4Addr::LOCALHOST.octets(),
            ),
            RecordType::AAAA => facade.add_answer(
                query.get_query_name(),
                resource_type,
                DNSClass::IN.into(),
                3600,
                &Ipv6Addr::LOCALHOST.octets(),
            ),
            _ => return make_not_implemented_error(facade),
        };
    }
    facade.get_length()
}

fn display(opcode: u8) -> &'static str {
    match OpCode::from_u8(opcode) {
        Ok(OpCode::Notify) => "Notify",
        Ok(OpCode::Query) => "Query",
        Ok(OpCode::Status) => "Status",
        Ok(OpCode::Update) => "Update",
        _ => "<unknown>",
    }
}

fn make_format_error(facade: &mut PacketFacade<'_>) -> usize {
    make_error(facade, ResponseCode::FormErr.low())
}

fn make_not_implemented_error(facade: &mut PacketFacade<'_>) -> usize {
    make_error(facade, ResponseCode::NotImp.low())
}

fn make_error(facade: &mut PacketFacade<'_>, response_code: u8) -> usize {
    facade.set_query(false);
    facade.set_authoritative_answer(false);
    facade.set_truncated(false);
    facade.set_recursion_available(true);
    facade.set_authenticated_data(false);
    facade.set_checking_disabled(false);
    facade.set_rcode(response_code);
    facade.clear();
    HEADER_BYTES
}

fn write_log(from: &RequestRecord, to: &ResponseRecord, addr: &SocketAddr, logger: &Logger) {
    if logger.trace_enabled() {
        let mut query_list = String::new();
        for query in from.queries.as_slice() {
            if !query_list.is_empty() {
                query_list += ", "
            }
            let query_class = query.get_query_class();
            let class_string = match DNSClass::from_u16(query_class) {
                Ok(c) => <&'static str>::from(c),
                Err(_) => UNKNOWN,
            };
            let _ = write!(
                query_list,
                "{}/{}/{}",
                RecordType::from(query.get_query_type()),
                class_string,
                query.get_query_name()
            );
        }
        let mut answer_list = String::new();
        for answer in to.answers.as_slice() {
            if !answer_list.is_empty() {
                answer_list += ", "
            }

            let rdata = answer.get_rdata();

            match rdata.len() {
                4 => {
                    let v4data = <&[u8; 4]>::try_from(rdata).expect("magically different size");
                    answer_list += &Ipv4Addr::from(*v4data).to_string();
                }
                16 => {
                    let v6data = <&[u8; 16]>::try_from(rdata).expect("magically different size");
                    answer_list += &Ipv6Addr::from(*v6data).to_string();
                }
                _ => answer_list += "<unintelligible>",
            };
        }

        trace!(
            logger,
            "{}ns: {} {} ({}) -> {} ({})",
            to.latency_ns,
            addr,
            display(from.opcode),
            &query_list,
            ResponseCode::from(0, to.rcode),
            &answer_list
        );
    }
}

struct RequestRecord {
    timestamp: Instant,
    opcode: u8,
    queries: Vec<Query>,
}

struct ResponseRecord {
    latency_ns: u64,
    rcode: u8,
    answers: Vec<ResourceRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;
    use std::time::Instant;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(HEADER_BYTES, 12);
        assert_eq!(UNKNOWN, "<unknown>");
    }

    #[test]
    fn returns_format_error_if_queries_overrun() {
        let memory: [u8; 100] = [0; 100];
        let mut correct_buf: Vec<u8> = Vec::from(&memory[0..memory.len()]);
        let correct_length = {
            let mut facade = PacketFacade::new(&mut correct_buf, HEADER_BYTES);
            facade.set_transaction_id(0x1234);
            facade.set_query(true);
            facade.set_recursion_available(false);
            facade.set_recursion_desired(false);
            facade.set_opcode(OpCode::Query.into());
            facade.add_query("name", RecordType::A.into(), DNSClass::IN.into());
            facade.get_length()
        };
        let truncated_length = correct_length - 1;
        let truncated_buf = &mut correct_buf[0..truncated_length];
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));

        let result = process(truncated_buf, truncated_length, &addr, &Logger::new(""));

        check_format_error_message(truncated_buf, 0x1234);
        assert_eq!(result, HEADER_BYTES);
    }

    #[test]
    fn returns_not_implemented_error_if_opcode_is_other_than_query() {
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut facade = PacketFacade::new(&mut buf, 500);
            facade.set_transaction_id(0x1234);
            facade.set_query(true);
            facade.set_recursion_available(false);
            facade.set_recursion_desired(false);
            facade.set_opcode(OpCode::Status.into());

            facade.add_query("name", RecordType::A.into(), DNSClass::IN.into());
            facade.get_length()
        };
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));

        let rsp_length = process(&mut buf, req_length, &addr, &Logger::new(""));

        check_not_implemented_error_message(&mut buf, 0x1234, OpCode::Status.into());
        assert_eq!(rsp_length, HEADER_BYTES);
    }

    #[test]
    fn returns_not_implemented_error_if_query_type_is_other_than_a_or_aaaa() {
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut facade = PacketFacade::new(&mut buf, 500);
            facade.set_transaction_id(0x1234);
            facade.set_query(true);
            facade.set_recursion_available(false);
            facade.set_recursion_desired(false);
            facade.set_opcode(OpCode::Query.into());
            facade.add_query("name", RecordType::NS.into(), DNSClass::IN.into());
            facade.get_length()
        };
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));

        let rsp_length = process(&mut buf, req_length, &addr, &Logger::new(""));

        check_not_implemented_error_message(&mut buf, 0x1234, OpCode::Query.into());
        assert_eq!(rsp_length, HEADER_BYTES);
    }

    #[test]
    fn returns_not_implemented_error_if_query_class_is_other_than_in() {
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut facade = PacketFacade::new(&mut buf, 500);
            facade.set_transaction_id(0x1234);
            facade.set_query(true);
            facade.set_recursion_available(false);
            facade.set_recursion_desired(false);
            facade.set_opcode(OpCode::Query.into());
            facade.add_query("name", RecordType::A.into(), DNSClass::CH.into());
            facade.get_length()
        };
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));

        let rsp_length = process(&mut buf, req_length, &addr, &Logger::new(""));

        check_not_implemented_error_message(&mut buf, 0x1234, OpCode::Query.into());
        assert_eq!(rsp_length, HEADER_BYTES);
    }

    #[test]
    fn two_queries_are_answered() {
        init_test_logging();
        let mut buf: [u8; 500] = [0; 500];
        let req_length = {
            let mut request = PacketFacade::new(&mut buf, 500);
            assert_eq!(request.set_transaction_id(0x4321), true);
            assert_eq!(request.set_query(true), true);
            assert_eq!(request.set_truncated(false), true);
            assert_eq!(request.set_recursion_desired(false), true);
            assert_eq!(request.set_checking_disabled(false), true);
            assert_eq!(request.set_opcode(OpCode::Query.into()), true);
            assert_eq!(
                request.add_query("ooga.com", RecordType::A.into(), DNSClass::IN.into()),
                true
            );
            assert_eq!(
                request.add_query("booga.com", RecordType::AAAA.into(), DNSClass::IN.into()),
                true
            );
            request.get_length()
        };
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        let rsp_length = {
            process(
                &mut buf,
                req_length,
                &addr,
                &Logger::new("two_queries_are_answered"),
            )
        };

        {
            let response = PacketFacade::new(&mut buf, rsp_length);

            assert_eq!(response.get_transaction_id(), Some(0x4321));
            assert_eq!(response.is_query(), Some(false));
            assert_eq!(response.get_opcode(), Some(OpCode::Query.into()));
            assert_eq!(response.is_authoritative_answer(), Some(false));
            assert_eq!(response.is_truncated(), Some(false));
            assert_eq!(response.is_recursion_desired(), Some(false));
            assert_eq!(response.is_recursion_available(), Some(true));
            assert_eq!(response.get_z(), Some(false));
            assert_eq!(response.is_authenticated_data(), Some(false));
            assert_eq!(response.is_checking_disabled(), Some(false));
            assert_eq!(response.get_rcode(), Some(ResponseCode::NoError.low()));
            let queries = response.get_queries().unwrap();
            assert_eq!(queries[0].get_query_name(), "ooga.com");
            assert_eq!(queries[0].get_query_type(), u16::from(RecordType::A));
            assert_eq!(queries[0].get_query_class(), u16::from(DNSClass::IN));
            assert_eq!(queries[1].get_query_name(), "booga.com");
            assert_eq!(queries[1].get_query_type(), u16::from(RecordType::AAAA));
            assert_eq!(queries[1].get_query_class(), u16::from(DNSClass::IN));
            assert_eq!(queries.len(), 2);
            let answers = response.get_answers().unwrap();
            assert_eq!(answers[0].get_name(), "ooga.com");
            assert_eq!(answers[0].get_resource_type(), u16::from(RecordType::A));
            assert_eq!(answers[0].get_resource_class(), u16::from(DNSClass::IN));
            assert_eq!(answers[0].get_time_to_live(), 3600);
            assert_eq!(answers[0].get_rdata(), vec![127, 0, 0, 1].as_slice());
            assert_eq!(answers[1].get_name(), "booga.com");
            assert_eq!(answers[1].get_resource_type(), u16::from(RecordType::AAAA));
            assert_eq!(answers[1].get_resource_class(), u16::from(DNSClass::IN));
            assert_eq!(answers[1].get_time_to_live(), 3600);
            assert_eq!(
                answers[1].get_rdata(),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].as_slice()
            );
            assert_eq!(answers.len(), 2);
            assert_eq!(response.get_authorities().unwrap().len(), 0);
            assert_eq!(response.get_additionals().unwrap().len(), 0);
        }

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "101.102.103.104:53 Query (A/IN/ooga.com, AAAA/IN/booga.com) -> No Error (127.0.0.1, ::1)",
        );
    }

    #[test]
    fn write_log_produces_correct_text() {
        init_test_logging();
        let request_record = RequestRecord {
            timestamp: Instant::now(),
            opcode: OpCode::Query.into(),
            queries: vec![
                Query::new_for_test(
                    String::from("first"),
                    RecordType::A.into(),
                    DNSClass::IN.into(),
                    11,
                ),
                Query::new_for_test(
                    String::from("second"),
                    RecordType::AAAA.into(),
                    DNSClass::IN.into(),
                    12,
                ),
            ],
        };
        let response_record = ResponseRecord {
            latency_ns: 2345,
            rcode: ResponseCode::FormErr.low(),
            answers: vec![
                ResourceRecord::new_for_test(
                    String::from("first"),
                    0x1234,
                    0x2345,
                    0x34567890,
                    vec![123, 124, 125, 126],
                    21,
                ),
                ResourceRecord::new_for_test(
                    String::from("second"),
                    0x3456,
                    0x4567,
                    0x4567890A,
                    vec![
                        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00,
                        0x00, 0x42, 0x83, 0x29,
                    ],
                    22,
                ),
            ],
        };

        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        {
            write_log(
                &request_record,
                &response_record,
                &addr,
                &Logger::new("write_log_produces_correct_text"),
            );
        }

        TestLogHandler::new().exists_log_containing("2345ns: 101.102.103.104:53 Query (A/IN/first, AAAA/IN/second) -> Form Error (123.124.125.126, 2001:db8::ff00:42:8329)");
    }

    #[test]
    fn write_log_when_rdata_is_not_a_recognized_size() {
        init_test_logging();
        let request_record = RequestRecord {
            timestamp: Instant::now(),
            opcode: OpCode::Query.into(),
            queries: vec![Query::new_for_test(
                String::from("first"),
                RecordType::A.into(),
                DNSClass::IN.into(),
                11,
            )],
        };
        let response_record = ResponseRecord {
            latency_ns: 2345,
            rcode: ResponseCode::FormErr.low(),
            answers: vec![ResourceRecord::new_for_test(
                String::from("first"),
                0x1234,
                0x2345,
                0x34567890,
                vec![],
                21,
            )],
        };

        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        {
            write_log(
                &request_record,
                &response_record,
                &addr,
                &Logger::new("write_log_produces_correct_text"),
            );
        }

        TestLogHandler::new().exists_log_containing(
            "2345ns: 101.102.103.104:53 Query (A/IN/first) -> Form Error (<unintelligible>)",
        );
    }

    #[test]
    fn write_log_when_opcode_is_not_recognized() {
        init_test_logging();
        let request_record = RequestRecord {
            timestamp: Instant::now(),
            opcode: 7,
            queries: vec![Query::new_for_test(
                String::from("first"),
                RecordType::A.into(),
                DNSClass::IN.into(),
                11,
            )],
        };
        let response_record = ResponseRecord {
            latency_ns: 2345,
            rcode: ResponseCode::FormErr.low(),
            answers: vec![ResourceRecord::new_for_test(
                String::from("first"),
                0x1234,
                0x2345,
                0x34567890,
                vec![123, 124, 125, 126],
                21,
            )],
        };

        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        {
            write_log(
                &request_record,
                &response_record,
                &addr,
                &Logger::new("write_log_produces_correct_text"),
            );
        }

        TestLogHandler::new().exists_log_containing(
            "2345ns: 101.102.103.104:53 <unknown> (A/IN/first) -> Form Error (123.124.125.126)",
        );
    }

    #[test]
    fn write_log_when_class_is_not_recognized() {
        init_test_logging();
        let request_record = RequestRecord {
            timestamp: Instant::now(),
            opcode: OpCode::Query.into(),
            queries: vec![Query::new_for_test(
                String::from("first"),
                RecordType::A.into(),
                167,
                11,
            )],
        };
        let response_record = ResponseRecord {
            latency_ns: 2345,
            rcode: ResponseCode::FormErr.low(),
            answers: vec![ResourceRecord::new_for_test(
                String::from("first"),
                0x1234,
                0x2345,
                0x34567890,
                vec![123, 124, 125, 126],
                21,
            )],
        };

        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(101, 102, 103, 104), 53));
        {
            write_log(
                &request_record,
                &response_record,
                &addr,
                &Logger::new("write_log_produces_correct_text"),
            );
        }

        TestLogHandler::new().exists_log_containing(
            "2345ns: 101.102.103.104:53 Query (A/<unknown>/first) -> Form Error (123.124.125.126)",
        );
    }

    fn check_format_error_message(mut buf: &mut [u8], transaction_id: u16) {
        let facade = PacketFacade::new(&mut buf, HEADER_BYTES);
        assert_eq!(facade.get_transaction_id(), Some(transaction_id));
        assert_eq!(facade.is_query(), Some(false));
        assert_eq!(facade.get_opcode(), Some(OpCode::Query.into()));
        assert_eq!(facade.is_authoritative_answer(), Some(false));
        assert_eq!(facade.is_truncated(), Some(false));
        assert_eq!(facade.is_recursion_desired(), Some(false));
        assert_eq!(facade.is_recursion_available(), Some(true));
        assert_eq!(facade.get_z(), Some(false));
        assert_eq!(facade.is_authenticated_data(), Some(false));
        assert_eq!(facade.is_checking_disabled(), Some(false));
        assert_eq!(facade.get_rcode(), Some(ResponseCode::FormErr.low()));
        assert_eq!(facade.get_queries().unwrap().len(), 0);
        assert_eq!(facade.get_answers().unwrap().len(), 0);
        assert_eq!(facade.get_authorities().unwrap().len(), 0);
        assert_eq!(facade.get_additionals().unwrap().len(), 0);
        assert_eq!(facade.get_length(), HEADER_BYTES);
    }

    fn check_not_implemented_error_message(mut buf: &mut [u8], transaction_id: u16, opcode: u8) {
        let facade = PacketFacade::new(&mut buf, HEADER_BYTES);
        assert_eq!(facade.get_transaction_id(), Some(transaction_id));
        assert_eq!(facade.is_query(), Some(false));
        assert_eq!(facade.get_opcode(), Some(opcode));
        assert_eq!(facade.is_authoritative_answer(), Some(false));
        assert_eq!(facade.is_truncated(), Some(false));
        assert_eq!(facade.is_recursion_desired(), Some(false));
        assert_eq!(facade.is_recursion_available(), Some(true));
        assert_eq!(facade.get_z(), Some(false));
        assert_eq!(facade.is_authenticated_data(), Some(false));
        assert_eq!(facade.is_checking_disabled(), Some(false));
        assert_eq!(facade.get_rcode(), Some(ResponseCode::NotImp.low()));
        assert_eq!(facade.get_queries().unwrap().len(), 0);
        assert_eq!(facade.get_answers().unwrap().len(), 0);
        assert_eq!(facade.get_authorities().unwrap().len(), 0);
        assert_eq!(facade.get_additionals().unwrap().len(), 0);
        assert_eq!(facade.get_length(), HEADER_BYTES);
    }
}
