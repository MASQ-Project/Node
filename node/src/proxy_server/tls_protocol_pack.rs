// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::{ProtocolPack, ServerImpersonator};
use crate::proxy_server::server_impersonator_tls::ServerImpersonatorTls;
use crate::sub_lib::binary_traverser::BinaryTraverser;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::host::Host;
use crate::sub_lib::proxy_server::ProxyProtocol;
use masq_lib::constants::TLS_PORT;

#[derive(Clone, Copy)]
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

    fn describe_packet(&self, data: &PlainData) -> String {
        match data.get_u8(0) {
            Some(0x16u8) => self.describe_handshake(data),
            Some(0x14u8) => self.describe_cipher_spec(data),
            Some(0x15u8) => self.describe_alert(data),
            Some(0x17u8) => self.describe_application_data(data),
            Some(opcode) => format!(
                "{}-byte packet of unrecognized type 0x{:02X}",
                data.len(),
                opcode
            ),
            None => format!("Incomplete {}-byte TLS packet", data.len()),
        }
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

    fn describe_handshake(&self, data: &PlainData) -> String {
        match data.get_u8(5) {
            Some(0x00u8) => "HelloRequest".to_string(),
            Some(0x01u8) => self.describe_client_hello(data),
            Some(0x02u8) => "ServerHello".to_string(),
            Some(0x03u8) => "HelloVerifyRequest".to_string(),
            Some(0x04u8) => "NewSessionTicket".to_string(),
            Some(0x05u8) => "EndOfEarlyData".to_string(),
            Some(0x06u8) => "HelloRetryRequest".to_string(),
            Some(0x0Bu8) => "Certificate".to_string(),
            Some(0x0Cu8) => "ServerKeyExchange".to_string(),
            Some(0x0Du8) => "CertificateRequest".to_string(),
            Some(0x0Eu8) => "ServerHelloDone".to_string(),
            Some(0x0Fu8) => "CertificateVerify".to_string(),
            Some(0x10u8) => "ClientKeyExchange".to_string(),
            Some(0x14u8) => "Finished".to_string(),
            Some(opcode) => format!("Unrecognized Handshake 0x{:02X}", opcode),
            None => format!("Incomplete {}-byte Handshake packet", data.len()),
        }
    }

    fn describe_client_hello(&self, data: &PlainData) -> String {
        match self.find_host(data) {
            Some(host) => format!("ClientHello with SNI '{}'", host.name),
            None => "ClientHello with no SNI extension".to_string(),
        }
    }

    fn describe_cipher_spec(&self, data: &PlainData) -> String {
        match data.get_u8(5) {
            Some(0x01u8) => "ChangeCipherSpec".to_string(),
            Some(opcode) => format!("Unrecognized ChangeCipherSpec 0x{:02X}", opcode),
            None => format!("Incomplete {}-byte ChangeCipherSpec packet", data.len()),
        }
    }

    fn describe_alert(&self, data: &PlainData) -> String {
        let level = match data.get_u8(5) {
            Some(0x01u8) => "Warning".to_string(),
            Some(0x02u8) => "Fatal".to_string(),
            Some(opcode) => format!("Unrecognized Alert Level 0x{:02X}", opcode),
            None => return format!("Incomplete {}-byte Alert packet", data.len()),
        };
        let description = match data.get_u8(6) {
            Some(0x00) => "CloseNotify".to_string(),
            Some(0x01) => "Unrecognized Alert Description 0x01".to_string(),
            Some(0x0A) => "UnexpectedMessage".to_string(),
            Some(0x14) => "BadRecordMAC".to_string(),
            Some(0x15) => "DecryptionFailed".to_string(),
            Some(0x16) => "RecordOverflow".to_string(),
            Some(0x1E) => "DecompressionFailure".to_string(),
            Some(0x28) => "HandshakeFailure".to_string(),
            Some(0x29) => "NoCertificate".to_string(),
            Some(0x2A) => "BadCertificate".to_string(),
            Some(0x2B) => "UnsupportedCertificate".to_string(),
            Some(0x2C) => "CertificateRevoked".to_string(),
            Some(0x2D) => "CertificateExpired".to_string(),
            Some(0x2E) => "CertificateUnknown".to_string(),
            Some(0x2F) => "IllegalParameter".to_string(),
            Some(0x30) => "UnknownCA".to_string(),
            Some(0x31) => "AccessDenied".to_string(),
            Some(0x32) => "DecodeError".to_string(),
            Some(0x33) => "DecryptError".to_string(),
            Some(0x3C) => "ExportRestriction".to_string(),
            Some(0x46) => "ProtocolVersion".to_string(),
            Some(0x47) => "InsufficientSecurity".to_string(),
            Some(0x50) => "InternalError".to_string(),
            Some(0x5A) => "UserCanceled".to_string(),
            Some(0x64) => "NoRenegotiation".to_string(),
            Some(0x72) => "UnsupportedExtension".to_string(),
            Some(opcode) => format!("Unrecognized Alert Description 0x{:02X}", opcode),
            None => return format!("Incomplete {}-byte Alert packet", data.len()),
        };
        format!("{} {}", level, description)
    }

    fn describe_application_data(&self, data: &PlainData) -> String {
        format!("{}-byte ApplicationData", data.len() - 5)
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

    #[test]
    fn describe_packet_handles_empty_packet() {
        let data = PlainData::new(&[]);

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("Incomplete 0-byte TLS packet", result);
    }

    #[test]
    fn describe_packet_handles_unrecognized_packet_type() {
        let data = PlainData::new(&[0xFFu8]);

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("1-byte packet of unrecognized type 0xFF", result);
    }

    #[test]
    fn describe_packet_handles_short_handshake_packet() {
        let data = PlainData::new(&[0x16u8]);

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("Incomplete 1-byte Handshake packet", result);
    }

    #[test]
    fn identifies_client_hello_with_sni() {
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

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("ClientHello with SNI 'server.com'", result);
    }

    #[test]
    fn identifies_client_hello_without_sni() {
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

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("ClientHello with no SNI extension", result);
    }

    #[test]
    fn identifies_other_handshakes() {
        #[rustfmt::skip]
        let mut bytes: Vec<u8> = vec![
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x00, // handshake_type: replace me
        ];
        let handshake_types = vec![
            (0x00, "HelloRequest"),
            (0x02, "ServerHello"),
            (0x03, "HelloVerifyRequest"),
            (0x04, "NewSessionTicket"),
            (0x05, "EndOfEarlyData"),
            (0x06, "HelloRetryRequest"),
            (0x07, "Unrecognized Handshake 0x07"),
            (0x08, "Unrecognized Handshake 0x08"),
            (0x0B, "Certificate"),
            (0x0C, "ServerKeyExchange"),
            (0x0D, "CertificateRequest"),
            (0x0E, "ServerHelloDone"),
            (0x0F, "CertificateVerify"),
            (0x10, "ClientKeyExchange"),
            (0x14, "Finished"),
        ];
        handshake_types.iter().for_each(|(opcode, name)| {
            bytes[5] = *opcode;
            let data = PlainData::new(&bytes);

            let result = TlsProtocolPack {}.describe_packet(&data);

            assert_eq!(*name, result);
        });
    }

    #[test]
    fn identifies_cipher_spec_packets() {
        #[rustfmt::skip]
        let mut bytes: Vec<u8> = vec![
            0x14, // content_type: ChangeCipherSpec
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x00, // change_cipher_spec: replace me
        ];
        let change_cipher_specs = vec![
            (0x00, "Unrecognized ChangeCipherSpec 0x00"),
            (0x01, "ChangeCipherSpec"),
            (0x02, "Unrecognized ChangeCipherSpec 0x02"),
        ];
        change_cipher_specs.iter().for_each(|(opcode, name)| {
            bytes[5] = *opcode;
            let data = PlainData::new(&bytes);

            let result = TlsProtocolPack {}.describe_packet(&data);

            assert_eq!(*name, result);
        });
    }

    #[test]
    fn handles_incomplete_cipher_spec_packet() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x14, // content_type: ChangeCipherSpec
        ]);

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("Incomplete 1-byte ChangeCipherSpec packet", result);
    }

    #[test]
    fn identifies_alert_packets() {
        #[rustfmt::skip]
        let mut bytes: Vec<u8> = vec![
            0x15, // content_type: Alert
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x00, // alert_level: replace me
            0x00, // alert_description: replace me
        ];
        let alert_levels = vec![
            (0x01, "Warning"),
            (0x02, "Fatal"),
            (0x03, "Unrecognized Alert Level 0x03"),
            (0x04, "Unrecognized Alert Level 0x04"),
        ];
        let alert_descriptions = vec![
            (0x00, "CloseNotify"),
            (0x01, "Unrecognized Alert Description 0x01"),
            (0x0A, "UnexpectedMessage"),
            (0x14, "BadRecordMAC"),
            (0x15, "DecryptionFailed"),
            (0x16, "RecordOverflow"),
            (0x1E, "DecompressionFailure"),
            (0x28, "HandshakeFailure"),
            (0x29, "NoCertificate"),
            (0x2A, "BadCertificate"),
            (0x2B, "UnsupportedCertificate"),
            (0x2C, "CertificateRevoked"),
            (0x2D, "CertificateExpired"),
            (0x2E, "CertificateUnknown"),
            (0x2F, "IllegalParameter"),
            (0x30, "UnknownCA"),
            (0x31, "AccessDenied"),
            (0x32, "DecodeError"),
            (0x33, "DecryptError"),
            (0x3C, "ExportRestriction"),
            (0x46, "ProtocolVersion"),
            (0x47, "InsufficientSecurity"),
            (0x50, "InternalError"),
            (0x5A, "UserCanceled"),
            (0x64, "NoRenegotiation"),
            (0x72, "UnsupportedExtension"),
            (0xFF, "Unrecognized Alert Description 0xFF"),
        ];
        alert_descriptions
            .iter()
            .for_each(|(description, description_name)| {
                bytes[6] = *description;
                alert_levels.iter().for_each(|(level, level_name)| {
                    bytes[5] = *level;
                    let data = PlainData::new(&bytes);

                    let result = TlsProtocolPack {}.describe_packet(&data);

                    let expected = format!("{} {}", level_name, description_name);
                    assert_eq!(expected, result);
                });
            });
    }

    #[test]
    fn handles_incomplete_alert_packet() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x15, // content_type: Alert
        ]);

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("Incomplete 1-byte Alert packet", result);
    }

    #[test]
    fn identifies_application_data_packets() {
        #[rustfmt::skip]
        let data = PlainData::new(&[
            0x17, // content_type: ApplicationData
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, 0x02, 0x03, 0x04, 0x05, // data
        ]);

        let result = TlsProtocolPack {}.describe_packet(&data);

        assert_eq!("5-byte ApplicationData", result);
    }
}
