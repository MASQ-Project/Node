// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use http_protocol_pack::HttpProtocolPack;
use protocol_pack::ProtocolPack;
use std::collections::HashMap;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PlainData;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_key::StreamKey;
use tls_protocol_pack::TlsProtocolPack;

pub struct ClientRequestPayloadFactory {
    protocol_packs: HashMap<u16, Box<ProtocolPack>>,
}

impl ClientRequestPayloadFactory {
    pub fn new() -> ClientRequestPayloadFactory {
        let mut protocol_packs: HashMap<u16, Box<ProtocolPack>> = HashMap::new();
        protocol_packs.insert(80, Box::new(HttpProtocolPack {}));
        protocol_packs.insert(443, Box::new(TlsProtocolPack {}));
        ClientRequestPayloadFactory { protocol_packs }
    }

    pub fn make(
        &self,
        ibcd: &InboundClientData,
        stream_key: StreamKey,
        cryptde: &CryptDE,
        logger: &Logger,
    ) -> Option<ClientRequestPayload> {
        let origin_port = match ibcd.reception_port {
            None => {
                logger.error(format!(
                    "No origin port specified with {}-byte packet: {:?}",
                    ibcd.data.len(),
                    ibcd.data
                ));
                return None;
            }
            Some(origin_port) => origin_port,
        };
        let protocol_pack = match self.protocol_packs.get(&origin_port) {
            None => {
                logger.error(format!(
                    "No protocol associated with origin port {} for {}-byte packet: {:?}",
                    origin_port,
                    ibcd.data.len(),
                    &ibcd.data
                ));
                return None;
            }
            Some(protocol_pack) => protocol_pack,
        };
        let sequence_number = match ibcd.sequence_number {
            Some(sequence_number) => sequence_number,
            None => {
                logger.error(format!(
                    "internal error: got IBCD with no sequence number and {} bytes",
                    ibcd.data.len()
                ));
                return None;
            }
        };
        let host_name = protocol_pack.find_host_name(&PlainData::new(&ibcd.data));
        Some(ClientRequestPayload {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: ibcd.data.clone(),
                sequence_number,
                last_data: ibcd.last_data,
            },
            target_hostname: host_name,
            target_port: origin_port,
            protocol: protocol_pack.proxy_protocol(),
            originator_public_key: cryptde.public_key().clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::test_utils::make_meaningless_stream_key;

    #[test]
    fn handles_http() {
        let data = PlainData::new(&b"GET http://borkoed.com/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(80),
            sequence_number: Some(1),
            last_data: false,
            is_clandestine: false,
            data: data.data.clone(),
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");
        let subject = ClientRequestPayloadFactory::new();

        let result = subject.make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: data.data,
                    sequence_number: 1,
                    last_data: false
                },
                target_hostname: Some(String::from("borkoed.com")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: cryptde.public_key(),
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
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
            'o' as u8, 'm' as u8, // server_name
        ]);
        let ibcd = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            sequence_number: Some(0),
            reception_port: Some(443),
            last_data: false,
            is_clandestine: false,
            data: data.data.clone(),
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");
        let subject = ClientRequestPayloadFactory::new();

        let result = subject.make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: data.data,
                    sequence_number: 0,
                    last_data: false
                },
                target_hostname: Some(String::from("server.com")),
                target_port: 443,
                protocol: ProxyProtocol::TLS,
                originator_public_key: cryptde.public_key(),
            })
        );
    }

    #[test]
    fn handles_tls_without_hostname() {
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
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(443),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(0),
            data: data.data.clone(),
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");
        let subject = ClientRequestPayloadFactory::new();

        let result = subject.make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger);

        assert_eq!(
            result,
            Some(ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: data.data,
                    sequence_number: 0,
                    last_data: true
                },
                target_hostname: None,
                target_port: 443,
                protocol: ProxyProtocol::TLS,
                originator_public_key: cryptde.public_key(),
            })
        );
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_not_specified() {
        init_test_logging();
        let ibcd = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            sequence_number: Some(0),
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            data: vec![0x10, 0x11, 0x12],
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");
        let subject = ClientRequestPayloadFactory::new();

        let result = subject.make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(
            "ERROR: test: No origin port specified with 3-byte packet: [16, 17, 18]",
        );
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_unknown() {
        init_test_logging();
        let ibcd = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: Some(1234),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: true,
            data: vec![0x10, 0x11, 0x12],
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");
        let subject = ClientRequestPayloadFactory::new();

        let result = subject.make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger);

        assert_eq!(result, None);
        TestLogHandler::new ().exists_log_containing ("ERROR: test: No protocol associated with origin port 1234 for 3-byte packet: [16, 17, 18]");
    }

    #[test]
    fn use_sequence_from_inbound_client_data_in_client_request_payload() {
        let ibcd = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            reception_port: Some(80),
            sequence_number: Some(1),
            last_data: false,
            data: vec![0x10, 0x11, 0x12],
            is_clandestine: false,
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");

        let subject = ClientRequestPayloadFactory::new();

        let result = subject
            .make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger)
            .unwrap();

        assert_eq!(result.sequenced_packet.sequence_number, 1);
    }

    #[test]
    fn makes_no_payload_if_sequence_number_is_unknown() {
        init_test_logging();
        let ibcd = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            reception_port: Some(80),
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: vec![1, 3, 5, 7],
        };
        let cryptde = CryptDENull::new();
        let logger = Logger::new("test");

        let subject = ClientRequestPayloadFactory::new();

        let result = subject.make(&ibcd, make_meaningless_stream_key(), &cryptde, &logger);

        assert_eq!(result, None);

        TestLogHandler::new().exists_log_containing(
            "ERROR: test: internal error: got IBCD with no sequence number and 4 bytes",
        );
    }
}
