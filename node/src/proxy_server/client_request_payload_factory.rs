// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::from_ibcd;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use masq_lib::logger::Logger;

pub trait ClientRequestPayloadFactory {
    fn make(
        &self,
        ibcd: &InboundClientData,
        stream_key: StreamKey,
        cryptde: &dyn CryptDE,
        logger: &Logger,
    ) -> Option<ClientRequestPayload_0v1>;
}

#[derive(Default)]
pub struct ClientRequestPayloadFactoryReal {}

impl ClientRequestPayloadFactory for ClientRequestPayloadFactoryReal {
    fn make(
        &self,
        ibcd: &InboundClientData,
        stream_key: StreamKey,
        cryptde: &dyn CryptDE,
        logger: &Logger,
    ) -> Option<ClientRequestPayload_0v1> {
        let protocol_pack = from_ibcd(ibcd).map_err(|e| error!(logger, "{}", e)).ok()?;
        let sequence_number = match ibcd.sequence_number {
            Some(sequence_number) => sequence_number,
            None => {
                error!(
                    logger,
                    "internal error: got IBCD with no sequence number and {} bytes",
                    ibcd.data.len()
                );
                return None;
            }
        };
        let data = PlainData::new(&ibcd.data);
        let target_host = protocol_pack.find_host(&data);
        let (target_hostname_opt, target_port) = match target_host {
            Some(host) => (Some(host.name), host.port),
            None => (None, protocol_pack.standard_port()),
        };
        Some(ClientRequestPayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: ibcd.data.clone(),
                sequence_number,
                last_data: ibcd.last_data,
            },
            target_hostname: target_hostname_opt,
            target_port,
            protocol: protocol_pack.proxy_protocol(),
            originator_public_key: cryptde.public_key().clone(),
        })
    }
}

impl ClientRequestPayloadFactoryReal {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use crate::test_utils::main_cryptde;
    use masq_lib::constants::HTTP_PORT;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::SystemTime;

    #[test]
    fn handles_http_with_a_port() {
        let data = PlainData::new(&b"GET http://borkoed.com:2345/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let cryptde = main_cryptde();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let logger = Logger::new("test");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 1,
                    last_data: false
                },
                target_hostname: Some(String::from("borkoed.com")),
                target_port: 2345,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: cryptde.public_key().clone(),
            })
        );
    }

    #[test]
    fn handles_http_with_no_port() {
        let test_name = "handles_http_with_no_port";
        let data = PlainData::new(&b"GET http://borkoed.com/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let cryptde = main_cryptde();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 1,
                    last_data: false
                },
                target_hostname: Some(String::from("borkoed.com")),
                target_port: HTTP_PORT,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: cryptde.public_key().clone(),
            })
        );
    }

    #[test]
    fn handles_tls_with_hostname() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c', b'o', b'm', // server_name
        ]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            sequence_number: Some(0),
            reception_port: Some(443),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let stream_key = StreamKey::make_meaningless_stream_key();
        let cryptde = main_cryptde();
        let logger = Logger::new("test");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 0,
                    last_data: false
                },
                target_hostname: Some(String::from("server.com")),
                target_port: 443,
                protocol: ProxyProtocol::TLS,
                originator_public_key: cryptde.public_key().clone(),
            })
        );
    }

    #[test]
    fn handles_tls_without_hostname() {
        let test_name = "handles_tls_without_hostname";
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x00, // extensions_length
        ]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(443),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(0),
            data: data.clone().into(),
        };
        let cryptde = main_cryptde();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 0,
                    last_data: true
                },
                target_hostname: None,
                target_port: 443,
                protocol: ProxyProtocol::TLS,
                originator_public_key: cryptde.public_key().clone(),
            })
        );
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_not_specified() {
        init_test_logging();
        let test_name = "makes_no_payload_if_origin_port_is_not_specified";
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            sequence_number: Some(0),
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            data: vec![0x10, 0x11, 0x12],
        };
        let cryptde = main_cryptde();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: No origin port specified with 3-byte non-clandestine packet: [16, 17, 18]"),
        );
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_unknown() {
        init_test_logging();
        let test_name = "makes_no_payload_if_origin_port_is_unknown";
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(1234),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: true,
            data: vec![0x10, 0x11, 0x12],
        };
        let cryptde = main_cryptde();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: No protocol associated with origin port 1234 for 3-byte non-clandestine packet: [16, 17, 18]"));
    }

    #[test]
    fn use_sequence_from_inbound_client_data_in_client_request_payload() {
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            data: vec![0x10, 0x11, 0x12],
            is_clandestine: false,
        };
        let cryptde = main_cryptde();
        let logger = Logger::new("test");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject
            .make(
                &ibcd,
                StreamKey::make_meaningless_stream_key(),
                cryptde,
                &logger,
            )
            .unwrap();

        assert_eq!(result.sequenced_packet.sequence_number, 1);
    }

    #[test]
    fn makes_no_payload_if_sequence_number_is_unknown() {
        init_test_logging();
        let test_name = "makes_no_payload_if_sequence_number_is_unknown";
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            reception_port: Some(HTTP_PORT),
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: vec![1, 3, 5, 7],
        };
        let cryptde = main_cryptde();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: internal error: got IBCD with no sequence number and 4 bytes"
        ));
    }
}
