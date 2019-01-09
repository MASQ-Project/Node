// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use protocol_pack::ProtocolPack;
use sub_lib::cryptde::PlainData;
use sub_lib::proxy_server::ProxyProtocol;

pub struct TlsProtocolPack {}

impl ProtocolPack for TlsProtocolPack {
    fn proxy_protocol(&self) -> ProxyProtocol {
        ProxyProtocol::TLS
    }

    fn find_host_name(&self, data: &PlainData) -> Option<String> {
        if !TlsProtocolPack::is_handshake(&data) {
            return None;
        }
        if !TlsProtocolPack::is_client_hello(&data) {
            return None;
        }
        TlsProtocolPack::find_host_name(&data)
    }
}

impl TlsProtocolPack {
    fn is_handshake(data: &PlainData) -> bool {
        data.data.first() == Some(&0x16)
    }

    fn is_client_hello(data: &PlainData) -> bool {
        data.data[5] == 0x01
    }

    fn find_host_name(data: &PlainData) -> Option<String> {
        let session_id_offset = 43;
        let cipher_suites_offset = TlsProtocolPack::advance_past(data, session_id_offset, 1)?;
        let compression_methods_offset =
            TlsProtocolPack::advance_past(data, cipher_suites_offset, 2)?;
        let extensions_offset = TlsProtocolPack::advance_past(data, compression_methods_offset, 1)?;
        let extensions_end = TlsProtocolPack::advance_past(data, extensions_offset, 2)?;
        let mut extension_offset = extensions_offset + 2;
        while extension_offset < extensions_end {
            let extension_type = TlsProtocolPack::u16_from(data, extension_offset);
            if extension_type == 0x0000 {
                return TlsProtocolPack::host_name_from_extension(data, extension_offset);
            }
            extension_offset = TlsProtocolPack::advance_past(data, extension_offset + 2, 2)?;
        }
        None
    }

    fn host_name_from_extension(data: &PlainData, offset: usize) -> Option<String> {
        let server_name_list_offset = offset + 4;
        let server_name_list_end = TlsProtocolPack::advance_past(data, server_name_list_offset, 2)?;
        let mut server_name_list_entry_offset = server_name_list_offset + 2;
        while server_name_list_entry_offset < server_name_list_end {
            let server_name_type = TlsProtocolPack::u8_from(data, server_name_list_entry_offset);
            if server_name_type == 0x00 {
                return TlsProtocolPack::host_name_from_list_entry(
                    data,
                    server_name_list_entry_offset,
                );
            }
            server_name_list_entry_offset =
                TlsProtocolPack::advance_past(data, server_name_list_entry_offset + 1, 2)?;
        }
        None
    }

    fn host_name_from_list_entry(data: &PlainData, offset: usize) -> Option<String> {
        let server_name_length = TlsProtocolPack::u16_from(data, offset + 1);
        let server_name_offset = offset + 3;
        match String::from_utf8(Vec::from(
            &data.data[(server_name_offset)..(server_name_offset + server_name_length)],
        )) {
            Ok(hostname) => Some(hostname),
            Err(_) => None,
        }
    }

    fn advance_past(data: &PlainData, length_offset: usize, length_length: usize) -> Option<usize> {
        if length_offset + length_length > data.data.len() {
            return None;
        }
        let length = if length_length == 1 {
            TlsProtocolPack::u8_from(data, length_offset)
        } else {
            TlsProtocolPack::u16_from(data, length_offset)
        };
        Some(length_offset + length_length + length)
    }

    fn u8_from(data: &PlainData, offset: usize) -> usize {
        data.data[offset] as usize
    }

    fn u16_from(data: &PlainData, offset: usize) -> usize {
        (TlsProtocolPack::u8_from(data, offset) << 8) | TlsProtocolPack::u8_from(data, offset + 1)
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
    fn rejects_non_empty_packet_that_is_not_handshake() {
        vec![0x14u8, 0x015u8, 0x17u8]
            .iter()
            .for_each(|content_type| {
                let data = PlainData::new(&[*content_type]);

                let result = TlsProtocolPack {}.find_host_name(&data);

                assert_eq!(result, None, "content_type: {}", *content_type);
            });
    }

    #[test]
    fn rejects_empty_packet_as_non_handshake() {
        let data = PlainData::new(&[]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn rejects_packet_that_is_not_client_hello() {
        vec![0u8, 2u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 20u8]
            .iter()
            .for_each(|handshake_type| {
                let data = PlainData::new(&[0x16, 0x00, 0x00, 0x00, 0x00, *handshake_type]);

                let result = TlsProtocolPack {}.find_host_name(&data);

                assert_eq!(result, None, "handshake_type: {}", *handshake_type);
            });
    }

    #[test]
    fn rejects_packet_that_has_no_server_name_extension() {
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

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
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

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_session_id_length() {
        // Removing this directive will make the Windows and other builds argue over formatting
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
                  // truncated session_id_length
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_session_id() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0xFF, // session_id_length
            0x00, 0x00, // truncated session_id
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_cipher_suites_length() {
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
            0x00, // truncated cipher_suites_length
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_cipher_suites() {
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
            0x00, 0xFF, // cipher_suites_length
            0x00, // truncated cipher_suites
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_compression_methods_length() {
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
            0xFF, // truncated compression_methods_length
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_compression_methods() {
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
            0xFF, // compression_methods_length
            0x00, 0x00, 0x00, // truncated compression_methods
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_with_truncated_extensions_length() {
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
            0x00, // truncated extensions_length
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_packet_truncated_amid_extensions() {
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
            0x00, 0xFF, // extensions_length
            0xFF, 0xFF, // truncated extensions
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn does_not_panic_for_hostname_that_is_not_utf8() {
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
            0x00, 0x0,  // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 0xC3,
            0x28, 'm' as u8, // bad server_name
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }

    #[test]
    fn extracts_hostname_from_packet_with_only_server_name_extension() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
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
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
            'o' as u8, 'm' as u8, // server_name
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, Some(String::from("server.com")));
    }

    #[test]
    fn extracts_hostname_from_packet_with_sections_and_multiple_extensions() {
        let data = PlainData::new(&[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
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
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
            'o' as u8, 'm' as u8, // server_name
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, Some(String::from("server.com")));
    }

    #[test]
    fn doesnt_see_host_name_extension_that_is_outside_extensions_section() {
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
            0x00, 0x07, // extensions_length *** ONLY ONE EXTENSION, NOT BOTH ***
            0x00, 0xFF, // extension_type: not server_name
            0x00, 0x03, // extension_length
            0x01, 0x02, 0x03, // throw-away data for fake extension
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
            'o' as u8, 'm' as u8, // server_name
        ]);

        let result = TlsProtocolPack {}.find_host_name(&data);

        assert_eq!(result, None);
    }
}
