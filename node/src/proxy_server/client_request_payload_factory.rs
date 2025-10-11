// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::from_ibcd;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::host::Host;
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use masq_lib::logger::Logger;

pub trait ClientRequestPayloadFactory {
    fn make(
        &self,
        ibcd: &InboundClientData,
        stream_key: StreamKey,
        host_opt: Option<Host>,
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
        host_opt: Option<Host>,
        cryptde: &dyn CryptDE,
        logger: &Logger,
    ) -> Option<ClientRequestPayload_0v1> {
        let protocol_pack = from_ibcd(ibcd).map_err(|e| error!(logger, "{}", e)).ok()?;
        let host_from_ibcd = Box::new(|| {
            let data = PlainData::new(&ibcd.data);
            match protocol_pack.find_host(&data) {
                Some(host) => Ok(host),
                // So far we've only looked in the client packet; but this message will evaporate
                // unless there's no host information in host_opt (from ProxyServer's StreamInfo) either.
                None => Err(format!(
                    "No hostname information found in either client packet or ProxyServer for protocol {:?}",
                    protocol_pack.proxy_protocol()
                )),
            }
        });
        let target_host: Host = match host_from_ibcd() {
            Ok(host) => host,
            Err(e) => match host_opt {
                Some(host) => host,
                None => {
                    error!(logger, "{}", e);
                    return None;
                }
            },
        };
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
        Some(ClientRequestPayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: ibcd.data.clone(),
                sequence_number,
                last_data: ibcd.last_data,
            },
            target_hostname: target_host.name,
            target_port: target_host.port,
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
    use crate::bootstrapper::CryptDEPair;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use lazy_static::lazy_static;
    use masq_lib::constants::{HTTP_PORT, TLS_PORT};
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::SystemTime;

    lazy_static! {
        static ref CRYPTDE_PAIR: CryptDEPair = CryptDEPair::null();
    }

    #[test]
    fn ibcd_hostname_overrides_supplied_hostname() {
        let data = PlainData::new(&b"GET http://borkoed.com:1234/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let cryptde = CRYPTDE_PAIR.main.dup();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let logger = Logger::new("ibcd_hostname_overrides_supplied_hostname");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject
            .make(
                &ibcd,
                stream_key,
                Some(Host::new("ignored.com", 4321)),
                cryptde.as_ref(),
                &logger,
            )
            .unwrap();

        assert_eq!(result.target_hostname, String::from("borkoed.com"));
        assert_eq!(result.target_port, 1234);
    }

    #[test]
    fn uses_supplied_host_if_ibcd_does_not_have_one() {
        let test_name = "uses_supplied_hostname_if_ibcd_does_not_have_one";
        let data = PlainData::new(&[0x01, 0x02, 0x03]); // No host can be extracted here
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.into(),
        };
        let cryptde = CRYPTDE_PAIR.main.dup();
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let logger = Logger::new(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());
        let supplied_host = Host::new("supplied.com", 4321);

        let result = subject
            .make(
                &ibcd,
                stream_key,
                Some(supplied_host.clone()),
                cryptde.as_ref(),
                &logger,
            )
            .unwrap();

        assert_eq!(result.target_hostname, supplied_host.name);
    }

    #[test]
    fn logs_error_and_returns_none_if_no_ibcd_host_and_no_supplied_host() {
        init_test_logging();
        let test_name = "logs_error_and_returns_none_if_no_ibcd_hostname_and_no_supplied_hostname";
        let data = PlainData::new(&[0x01, 0x02, 0x03]); // no host can be extracted here
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.into(),
        };
        let cryptde = CRYPTDE_PAIR.main.dup();
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let logger = Logger::new(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde.as_ref(), &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: No hostname information found in either client packet or ProxyServer for protocol HTTP"));
    }

    #[test]
    fn handles_http_with_a_port() {
        let data = PlainData::new(&b"GET http://borkoed.com:2345/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let logger = Logger::new("test");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 1,
                    last_data: false
                },
                target_hostname: String::from("borkoed.com"),
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
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 1,
                    last_data: false
                },
                target_hostname: String::from("borkoed.com"),
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
            reception_port_opt: Some(443),
            last_data: false,
            is_clandestine: false,
            data: data.clone().into(),
        };
        let stream_key = StreamKey::make_meaningless_stream_key();
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new("test");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload_0v1 {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: data.into(),
                    sequence_number: 0,
                    last_data: false
                },
                target_hostname: String::from("server.com"),
                target_port: TLS_PORT,
                protocol: ProxyProtocol::TLS,
                originator_public_key: cryptde.public_key().clone(),
            })
        );
    }

    #[test]
    fn handles_tls_without_hostname() {
        init_test_logging();
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
            reception_port_opt: Some(443),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(0),
            data: data.clone().into(),
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: No hostname information found in either client packet or ProxyServer for protocol TLS"));
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_not_specified() {
        init_test_logging();
        let test_name = "makes_no_payload_if_origin_port_is_not_specified";
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            sequence_number: Some(0),
            reception_port_opt: None,
            last_data: false,
            is_clandestine: false,
            data: vec![0x10, 0x11, 0x12],
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

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
            reception_port_opt: Some(1234),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: true,
            data: vec![0x10, 0x11, 0x12],
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: No protocol associated with origin port 1234 for 3-byte non-clandestine packet: [16, 17, 18]"));
    }

    #[test]
    fn use_sequence_from_inbound_client_data_in_client_request_payload() {
        let data = PlainData::new(&b"GET http://borkoed.com/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(1),
            last_data: false,
            data: data.into(),
            is_clandestine: false,
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new("test");
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject
            .make(
                &ibcd,
                StreamKey::make_meaningless_stream_key(),
                None,
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
        let data = PlainData::new(&b"GET http://borkoed.com/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            reception_port_opt: Some(HTTP_PORT),
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: data.into(),
        };
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let logger = Logger::new(test_name);
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let subject = Box::new(ClientRequestPayloadFactoryReal::new());

        let result = subject.make(&ibcd, stream_key, None, cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: internal error: got IBCD with no sequence number and 47 bytes"
        ));
    }
}
