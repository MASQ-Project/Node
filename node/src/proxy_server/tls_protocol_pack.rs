// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::{Host, ProtocolPack, ServerImpersonator};
use crate::proxy_server::server_impersonator_tls::ServerImpersonatorTls;
use crate::sub_lib::binary_traverser::BinaryTraverser;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::proxy_server::ProxyProtocol;
use masq_lib::constants::TLS_PORT;

pub struct TlsProtocolPack {}

impl ProtocolPack for TlsProtocolPack {
    fn proxy_protocol(&self) -> ProxyProtocol {
        ProxyProtocol::TLS
    }

    fn standard_port(&self) -> u16 {
        TLS_PORT
    }

    fn find_host(&self, data: &PlainData) -> Option<Host> {
        let mut xvsr = BinaryTraverser::new(data);
        if !TlsProtocolPack::is_handshake(&mut xvsr) {
            return None;
        }
        if !TlsProtocolPack::is_client_hello(&mut xvsr) {
            return None;
        }
        match Self::host_name_from_client_hello(&mut xvsr) {
            Ok(name) => Some(Host {
                name,
                port: TLS_PORT,
            }),
            Err(()) => None,
        }
    }

    fn server_impersonator(&self) -> Box<dyn ServerImpersonator> {
        Box::new(ServerImpersonatorTls {})
    }
}

impl TlsProtocolPack {
    fn is_handshake(xvsr: &mut BinaryTraverser) -> bool {
        let handshake_content_type = 22u8;
        xvsr.get_u8() == Ok(handshake_content_type)
    }

    fn is_client_hello(xvsr: &mut BinaryTraverser) -> bool {
        let handshake_message_type_position = 5;
        let client_hello_message_type = 1u8;
        xvsr.advance(handshake_message_type_position - xvsr.offset())
            .expect("Internal Error");
        xvsr.get_u8() == Ok(client_hello_message_type)
    }

    fn host_name_from_client_hello(xvsr: &mut BinaryTraverser) -> Result<String, ()> {
        let session_id_length_position = 43;
        let server_name_extension_type = 0u16;
        xvsr.advance(session_id_length_position - xvsr.offset())?;
        let session_id_length = xvsr.get_u8()?;
        xvsr.advance(session_id_length as usize)?;
        let cipher_suites_length = xvsr.get_u16()?;
        xvsr.advance(cipher_suites_length as usize)?;
        let compression_methods_length = xvsr.get_u8()?;
        xvsr.advance(compression_methods_length as usize)?;
        let extensions_length = xvsr.get_u16()? as usize;
        let extensions_offset = xvsr.offset();
        while xvsr.offset() < (extensions_offset + extensions_length) {
            let extension_type = xvsr.get_u16()?;
            if extension_type == server_name_extension_type {
                return TlsProtocolPack::host_name_from_extension(xvsr);
            }
            let extension_length = xvsr.get_u16()?;
            xvsr.advance(extension_length as usize)?;
        }
        Err(())
    }

    fn host_name_from_extension(xvsr: &mut BinaryTraverser) -> Result<String, ()> {
        xvsr.advance(2)?;
        let server_name_list_length = xvsr.get_u16()? as usize;
        let server_name_list_end = xvsr.offset() + server_name_list_length;
        while xvsr.offset() < server_name_list_end {
            let server_name_type = xvsr.get_u8()?;
            if server_name_type == 0x00 {
                return Self::host_name_from_list_entry(xvsr);
            }
            let server_name_length = xvsr.get_u16()?;
            xvsr.advance(server_name_length as usize)?;
        }
        Err(())
    }

    fn host_name_from_list_entry(xvsr: &mut BinaryTraverser) -> Result<String, ()> {
        let server_name_length = xvsr.get_u16()?;
        let server_name_bytes = xvsr.next_bytes(server_name_length as usize)?;
        match String::from_utf8(Vec::from(server_name_bytes)) {
            Ok(hostname) => Ok(hostname),
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_its_protocol() {
        let result = TlsProtocolPack {}.proxy_protocol();

        assert_eq!(result, ProxyProtocol::TLS);
    }

    #[test]
    fn knows_its_standard_port() {
        let result = TlsProtocolPack {}.standard_port();

        assert_eq!(result, TLS_PORT);
    }

    #[test]
    fn rejects_non_empty_packet_that_is_not_handshake() {
        vec![0x14u8, 0x015u8, 0x17u8]
            .iter()
            .for_each(|content_type| {
                let data = PlainData::new(&[*content_type]);

                let result = TlsProtocolPack {}.find_host(&data);

                assert_eq!(None, result, "content_type: {}", *content_type);
            });
    }

    #[test]
    fn rejects_empty_packet_as_non_handshake() {
        let data = PlainData::new(&[]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn rejects_packet_that_is_not_client_hello() {
        vec![0u8, 2u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 20u8]
            .iter()
            .for_each(|handshake_type| {
                let data = PlainData::new(&[0x16, 0x00, 0x00, 0x00, 0x00, *handshake_type]);

                let result = TlsProtocolPack {}.find_host(&data);

                assert_eq!(None, result, "handshake_type: {}", *handshake_type);
            });
    }

    #[test]
    fn rejects_packet_that_has_no_server_name_extension() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x00, // extensions_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_zero_length_buffer() {
        let data = PlainData::new(&[]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_truncated_before_handshake_type() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_preamble() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // truncated preamble
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_session_id_length() {
        // Removing this directive will make the Windows and other builds argue over formatting
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
                  // truncated session_id_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_session_id() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0xFF, // session_id_length
            0x00, 0x00, // truncated session_id
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_cipher_suites_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, // truncated cipher_suites_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_cipher_suites() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0xFF, // cipher_suites_length
            0x00, // truncated cipher_suites
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_compression_methods_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0xFF, // truncated compression_methods_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_compression_methods() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0xFF, // compression_methods_length
            0x00, 0x00, 0x00, // truncated compression_methods
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_extensions_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, // truncated extensions_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_packet_truncated_amid_extensions() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0xFF, // extensions_length
            0xFF, 0xFF, // truncated extensions
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_hostname_that_is_not_utf8() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x0,  // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            b's', b'e', b'r', b'v', b'e', b'r', b'.', 0xC3,
            0x28, b'm', // bad server_name
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_main_length() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, // version: don't care
            0x7F, 0xFF, // length: OVERRUN
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_client_hello_length() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, // version: don't care
            0x00, 0x00, // length: don't care
            0x01, // handshake_type: ClientHello
            0x7F, 0xFF, 0xFF, // length: OVERRUN
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_session_id_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, // version: don't care
            0x00, 0x00, // length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, // length: don't care
            0x00, 0x00, // version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x7F, // session_id_length: OVERRUN
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_cipher_suites_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, // version: don't care
            0x00, 0x00, // length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, // length: don't care
            0x00, 0x00, // version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x7F, 0xFF, // cipher_suites_length: OVERRUN
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_compression_methods_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, // version: don't care
            0x00, 0x00, // length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, // length: don't care
            0x00, 0x00, // version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0xFF, // compression_methods_length: OVERRUN
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_extensions_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x7F, 0xFF, // extensions_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_preceding_extension_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x00, 0x20, // extensions_length
            0x00, 0xFF, // extension_type: not server_name
            0x7F, 0xFF, // extension_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_server_name_extension_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x00, 0x20, // extensions_length
            0x00, 0xFF, // extension_type: not server_name
            0x00, 0x03, // extension_length
            0x01, 0x02, 0x03, // throw-away data for fake extension
            0x00, 0xFE, // extension_type: not server_name
            0x00, 0x02, // extension_length
            0x05, 0x06, // throw-away data for fake extension
            0x00, 0x00, // extension_type: server_name
            0x7F, 0xFF, // extension_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_server_name_list_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x00, 0x20, // extensions_length
            0x00, 0xFF, // extension_type: not server_name
            0x00, 0x03, // extension_length
            0x01, 0x02, 0x03, // throw-away data for fake extension
            0x00, 0xFE, // extension_type: not server_name
            0x00, 0x02, // extension_length
            0x05, 0x06, // throw-away data for fake extension
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x7F, 0xFF, // server_name_list_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn does_not_panic_for_buffer_overrun_in_server_name_length() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x00, 0x20, // extensions_length
            0x00, 0xFF, // extension_type: not server_name
            0x00, 0x03, // extension_length
            0x01, 0x02, 0x03, // throw-away data for fake extension
            0x00, 0xFE, // extension_type: not server_name
            0x00, 0x02, // extension_length
            0x05, 0x06, // throw-away data for fake extension
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x7F, 0xFF, // server_name_length
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn extracts_hostname_from_packet_with_only_server_name_extension() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c',
            b'o', b'm', // server_name
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(
            Some(Host {
                name: String::from("server.com"),
                port: TLS_PORT,
            }),
            result
        );
    }

    #[test]
    fn extracts_hostname_from_packet_with_sections_and_multiple_extensions() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x01, // session_id_length
            0x00, // session_id: don't care
            0x00, 0x01, // cipher_suites_length
            0x00, // cipher_suite: don't care
            0x01, // compression_methods_length
            0x00, // compression_method: don't care
            0x00, 0x20, // extensions_length
            0x00, 0xFF, // extension_type: not server_name
            0x00, 0x03, // extension_length
            0x01, 0x02, 0x03, // throw-away data for fake extension
            0x00, 0xFE, // extension_type: not server_name
            0x00, 0x02, // extension_length
            0x05, 0x06, // throw-away data for fake extension
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c',
            b'o', b'm', // server_name
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(
            Some(Host {
                name: String::from("server.com"),
                port: TLS_PORT
            }),
            result
        );
    }

    #[test]
    fn doesnt_see_host_name_extension_that_is_outside_extensions_section() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x07, // extensions_length *** ONLY ONE EXTENSION, NOT BOTH ***
            0x00, 0xFF, // extension_type: not server_name
            0x00, 0x03, // extension_length
            0x01, 0x02, 0x03, // throw-away data for fake extension
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c',
            b'o', b'm', // server_name
        ]);

        let result = TlsProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }
}
