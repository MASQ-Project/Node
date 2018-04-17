// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashMap;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PlainData;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use http_protocol_pack::HttpProtocolPack;
use protocol_pack::ProtocolPack;
use tls_protocol_pack::TlsProtocolPack;

pub struct ClientRequestPayloadFactory {
    protocol_packs: HashMap<u16, Box<ProtocolPack>>
}

impl ClientRequestPayloadFactory {
    pub fn new () -> ClientRequestPayloadFactory {
        let mut protocol_packs: HashMap<u16, Box<ProtocolPack>> = HashMap::new ();
        protocol_packs.insert (80, Box::new (HttpProtocolPack{}));
        protocol_packs.insert (443, Box::new (TlsProtocolPack{}));
        ClientRequestPayloadFactory {
            protocol_packs
        }
    }

    pub fn make (&self, ibcd: &InboundClientData, cryptde: &CryptDE, logger: &Logger) -> Option<ClientRequestPayload> {
        let plain_data = PlainData::new (&ibcd.data);
        let origin_port = match ibcd.origin_port {
            None => {logger.error (format! ("No origin port specified with {}-byte packet: {:?}", plain_data.data.len (), &plain_data.data)); return None},
            Some (origin_port) => origin_port
        };
        let protocol_pack = match self.protocol_packs.get (&origin_port) {
            None => {logger.error (format! ("No protocol associated with origin port {} for {}-byte packet: {:?}", origin_port, plain_data.data.len (), &plain_data.data)); return None},
            Some (protocol_pack) => protocol_pack
        };
        let host_name = protocol_pack.find_host_name (&plain_data);
        Some (ClientRequestPayload {
            stream_key: ibcd.socket_addr,
            data: plain_data,
            target_hostname: host_name,
            target_port: origin_port,
            protocol: protocol_pack.proxy_protocol (),
            originator_public_key: cryptde.public_key().clone ()
        })
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::dispatcher::Component;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::TestLogHandler;

    #[test]
    fn handles_http () {
        let data = PlainData::new (&b"GET http://borko.com/fleebs.html HTTP/1.1\r\n\r\n"[..]);
        let ibcd = InboundClientData {
            socket_addr: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            origin_port: Some (80),
            component: Component::ProxyServer,
            data: data.data.clone (),
        };
        let cryptde = CryptDENull::new ();
        let logger = Logger::new ("test");
        let subject = ClientRequestPayloadFactory::new ();

        let result = subject.make (&ibcd, &cryptde, &logger);

        assert_eq! (result, Some (ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:5678").unwrap(),
            data,
            target_hostname: Some (String::from ("borko.com")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: cryptde.public_key (),
        }));
    }

    #[test]
    fn handles_tls_with_hostname () {
        let data = PlainData::new (&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8, 'o' as u8, 'm' as u8, // server_name
        ]);
        let ibcd = InboundClientData {
            socket_addr: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            origin_port: Some (443),
            component: Component::ProxyServer,
            data: data.data.clone (),
        };
        let cryptde = CryptDENull::new ();
        let logger = Logger::new ("test");
        let subject = ClientRequestPayloadFactory::new ();

        let result = subject.make (&ibcd, &cryptde, &logger);

        assert_eq! (result, Some (ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:5678").unwrap(),
            data,
            target_hostname: Some (String::from ("server.com")),
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: cryptde.public_key (),
        }));
    }

    #[test]
    fn handles_tls_without_hostname () {
        let data = PlainData::new (&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x00, // extensions_length
        ]);
        let ibcd = InboundClientData {
            socket_addr: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            origin_port: Some (443),
            component: Component::ProxyServer,
            data: data.data.clone (),
        };
        let cryptde = CryptDENull::new ();
        let logger = Logger::new ("test");
        let subject = ClientRequestPayloadFactory::new ();

        let result = subject.make (&ibcd, &cryptde, &logger);

        assert_eq! (result, Some (ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:5678").unwrap(),
            data,
            target_hostname: None,
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: cryptde.public_key (),
        }));
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_not_specified () {
        LoggerInitializerWrapperMock::new ().init ();
        let ibcd = InboundClientData {
            socket_addr: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            origin_port: None,
            component: Component::ProxyServer,
            data: vec!(0x10, 0x11, 0x12),
        };
        let cryptde = CryptDENull::new ();
        let logger = Logger::new ("test");
        let subject = ClientRequestPayloadFactory::new ();

        let result = subject.make (&ibcd, &cryptde, &logger);

        assert_eq! (result, None);
        TestLogHandler::new ().exists_log_containing ("ERROR: test: No origin port specified with 3-byte packet: [16, 17, 18]");
    }

    #[test]
    fn makes_no_payload_if_origin_port_is_unknown () {
        LoggerInitializerWrapperMock::new ().init ();
        let ibcd = InboundClientData {
            socket_addr: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            origin_port: Some (1234),
            component: Component::ProxyServer,
            data: vec!(0x10, 0x11, 0x12),
        };
        let cryptde = CryptDENull::new ();
        let logger = Logger::new ("test");
        let subject = ClientRequestPayloadFactory::new ();

        let result = subject.make (&ibcd, &cryptde, &logger);

        assert_eq! (result, None);
        TestLogHandler::new ().exists_log_containing ("ERROR: test: No protocol associated with origin port 1234 for 3-byte packet: [16, 17, 18]");
    }
}
