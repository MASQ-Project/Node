// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::{ProtocolPack, ServerImpersonator};
use crate::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::host::Host;
use crate::sub_lib::proxy_server::ProxyProtocol;
use lazy_static::lazy_static;
use masq_lib::constants::HTTP_PORT;
use masq_lib::utils::index_of;
use regex::Regex;

lazy_static! {
    static ref HOST_PATTERN: Regex = Regex::new(r"^(?:https?://)?([^\s/]+)").expect("bad regex");
}

#[derive(Clone, Copy)]
pub struct HttpProtocolPack {}

impl ProtocolPack for HttpProtocolPack {
    fn proxy_protocol(&self) -> ProxyProtocol {
        ProxyProtocol::HTTP
    }

    fn standard_port(&self) -> u16 {
        HTTP_PORT
    }

    fn find_host(&self, data: &PlainData) -> Option<Host> {
        match HttpProtocolPack::find_header_host(data.as_slice()) {
            Some(host) => Some(host),
            None => HttpProtocolPack::find_url_host(data.as_slice()),
        }
    }

    fn server_impersonator(&self) -> Box<dyn ServerImpersonator> {
        Box::new(ServerImpersonatorHttp {})
    }

    fn describe_packet(&self, data: &PlainData) -> String {
        if data.as_slice().starts_with(b"HTTP/") {
            self.describe_response(data)
        } else {
            self.describe_request(data)
        }
    }
}

impl HttpProtocolPack {
    fn find_url_host(data: &[u8]) -> Option<Host> {
        let idx = index_of(data, &b"\r\n"[..])?;
        let first_line = &data[0..idx];
        let path_begin = index_of(first_line, b" ")? + 1;
        let path_end = index_of(&data[path_begin..], &b" "[..])? + path_begin;
        let path = String::from_utf8(Vec::from(&data[path_begin..path_end])).ok()?;
        let host_name_and_port = HOST_PATTERN.captures(&path)?.get(1)?.as_str();
        let host_maybe = Self::host_from_host_name_and_port(host_name_and_port);

        match host_maybe {
            Some(ref host) if !&host.name.is_empty() => host_maybe,
            _ => None,
        }
    }

    fn find_header_host(data: &[u8]) -> Option<Host> {
        let idx = index_of(data, &b"\r\n\r\n"[..])?;
        let headers = &data[0..idx + 2];
        let needle = b"\r\nHost: ";
        let begin = index_of(headers, &needle[..])? + needle.len();
        let host_header_value =
            &headers[begin..(index_of(&headers[begin..], &b"\r\n"[..])? + begin)];
        let host_and_port = String::from_utf8(Vec::from(host_header_value)).ok()?;
        Self::host_from_host_name_and_port(&host_and_port)
    }

    fn host_from_host_name_and_port(host_and_port: &str) -> Option<Host> {
        let mut parts: Vec<&str> = host_and_port.split(':').collect();
        match parts.len() {
            1 => Some(Host {
                name: parts.remove(0).to_string(),
                port: HTTP_PORT,
            }),
            2 => {
                let name = parts.remove(0).to_string();
                match Self::port_from_string(parts.remove(0).to_string()) {
                    Ok(port) => Some(Host { name, port }),
                    Err(_) => None,
                }
            }
            _ => None,
        }
    }

    pub fn is_connect(data: &[u8]) -> bool {
        let method_bytes: Vec<u8> = data
            .iter()
            .take(8)
            .take_while(|c| c != &&b' ')
            .cloned()
            .collect();

        matches!(
            http::Method::from_bytes(method_bytes.as_slice()),
            Ok(http::Method::CONNECT)
        )
    }

    fn port_from_string(port_str: String) -> Result<u16, String> {
        match port_str.parse::<u16>() {
            Err(_) => Err(format!("Port '{}' is not a number", port_str)),
            Ok(port) => Ok(port),
        }
    }

    fn describe_request(&self, data: &PlainData) -> String {
        let first_line_end = data
            .as_slice()
            .iter()
            .position(|&b| b == b'\r')
            .unwrap_or(data.len());
        let first_line = &data.as_slice()[0..first_line_end];
        let mut parts = first_line.split(|&b| b == b' ');
        if let (Some(method_bytes), Some(path_bytes), Some(http_version_bytes)) =
            (parts.next(), parts.next(), parts.next())
        {
            let method = Self::from_utf8(method_bytes);
            let path = Self::from_utf8(path_bytes);
            let http_version = Self::from_utf8(http_version_bytes);
            if let Some(host) = self.find_host(data) {
                return if path.starts_with('/') {
                    format!(
                        "{} {} request to {}{}",
                        http_version, method, host.name, path
                    )
                } else {
                    format!("{} {} request to {}", http_version, method, path)
                };
            } else {
                return format!(
                    "{} {} request to unknown host: {}",
                    http_version, method, path
                );
            }
        }
        format!(
            "Malformed HTTP request: {}",
            Self::truncate_data_as_string(data, 50)
        )
    }

    fn describe_response(&self, data: &PlainData) -> String {
        let first_line_end = data
            .as_slice()
            .iter()
            .position(|&b| b == b'\r')
            .unwrap_or(data.as_slice().len());
        let first_line = &data.as_slice()[0..first_line_end];
        let mut parts = first_line.split(|&b| b == b' ');
        if let (Some(http_version_bytes), Some(status_code_bytes), Some(status_text_bytes)) =
            (parts.next(), parts.next(), parts.next())
        {
            let http_with_version = Self::from_utf8(http_version_bytes);
            let status_code = Self::from_utf8(status_code_bytes);
            let status_text = Self::from_utf8(status_text_bytes);
            return format!(
                "{} response with status {} {}",
                http_with_version, status_code, status_text
            );
        }
        format!(
            "Malformed HTTP response: {}",
            Self::truncate_data_as_string(data, 50)
        )
    }

    fn truncate_data_as_string(data: &PlainData, truncate_at: usize) -> String {
        if data.as_slice().len() > truncate_at {
            format!(
                "'{}'...",
                String::from_utf8_lossy(&data.as_slice()[0..truncate_at])
            )
        } else {
            format!("'{}'", String::from_utf8_lossy(data.as_slice()))
        }
    }

    fn from_utf8(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        let host_pattern_expected: Regex =
            Regex::new(r"^(?:https?://)?([^\s/]+)").expect("bad regex");
        assert_eq!(HOST_PATTERN.to_string(), host_pattern_expected.to_string());
    }

    #[test]
    fn knows_its_protocol() {
        let result = HttpProtocolPack {}.proxy_protocol();

        assert_eq!(ProxyProtocol::HTTP, result);
    }

    #[test]
    fn knows_its_standard_port() {
        let result = HttpProtocolPack {}.standard_port();

        assert_eq!(HTTP_PORT, result);
    }

    #[test]
    fn returns_none_if_no_double_crlf() {
        let data = PlainData::new(b"no\r\ndouble\r\ncrlf\r\n");

        let result = HttpProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn returns_none_if_double_crlf_but_no_hostname() {
        let data =
            PlainData::new(b"GET /nohostname.html HTTP/1.1\r\nContent-Length: 8\r\n\r\nbodybody");

        let result = HttpProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn returns_none_if_hostname_doesnt_end_properly() {
        let data = PlainData::new(b"POST /nohostname.html HTTP/1.1\r\nHost: improperly.ended");

        let result = HttpProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn returns_host_name_from_header() {
        let data = PlainData::new(
            b"OPTIONS /index.html HTTP/1.1\r\nHost: header.host.com\r\n\r\nbodybody",
        );

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("header.host.com", HTTP_PORT));
    }

    #[test]
    fn rejects_host_header_with_two_colons() {
        let data = PlainData::new(
            b"OPTIONS /index.html HTTP/1.1\r\nHost: header.host.com:1234:2345\r\n\r\nbodybody",
        );

        let result = HttpProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn failed_in_production_2019_26_04() {
        let data = PlainData::new(
            b"GET /index.html HTTP/1.1\r\nHost: 192.168.1.230\r\nUser-Agent: curl/7.47.0\r\nAccept:*/*\r\n\r\n"
        );

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("192.168.1.230", HTTP_PORT));
    }

    #[test]
    fn returns_host_name_and_port_from_header_if_both_exist() {
        let data = PlainData::new(b"OPTIONS http://top.host.com:1234/index.html HTTP/1.1\r\nHost: header.host.com:5432\r\n\r\nbodybody");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("header.host.com", 5432));
    }

    #[test]
    fn returns_host_name_from_http_url_if_header_doesnt_exist() {
        // Note: that "Host: body.host.com" looks like a header, but it's not: it's content.
        let data = PlainData::new(b"DELETE http://top.host.com/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host.name, String::from("top.host.com"));
    }

    #[test]
    fn returns_host_name_from_https_url_if_header_doesnt_exist() {
        // Note: that "Host: body.host.com" looks like a header, but it's not: it's content.
        let data = PlainData::new(b"PUT https://top.host.com/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
    }

    #[test]
    fn returns_host_name_even_when_no_path() {
        let data = PlainData::new(b"PROXY http://top.host.com HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("top.host.com", HTTP_PORT));
    }

    #[test]
    fn returns_host_name_from_url_when_no_scheme() {
        let data = PlainData::new(b"GET good.url.dude/path.html HTTP/1.0\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host.name, String::from("good.url.dude"));
    }

    #[test]
    fn can_handle_domain_that_starts_with_http() {
        let data =
            PlainData::new(b"GET bad.url.dude/path.html HTTP/1.1\r\nHost: http.url.dude\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("http.url.dude"), host.name);
    }

    #[test]
    fn specifying_a_port_in_the_url() {
        let data = PlainData::new(b"HEAD http://top.host.com:8080/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("top.host.com", 8080));
    }

    #[test]
    fn specifying_two_colons_in_the_url() {
        let data = PlainData::new(b"HEAD http://top.host.com:8080:1234/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let result = HttpProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn specifying_a_non_numeric_port_in_the_url() {
        let data = PlainData::new(b"HEAD http://top.host.com:nanan/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data);

        assert_eq!(host, None);
    }

    #[test]
    fn cant_extract_top_host_if_port_has_syntax_error() {
        let data = PlainData::new(b"HEAD http://top.host.com:/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data);

        assert_eq!(host, None);
    }

    #[test]
    fn explicit_port_is_80_if_it_was_not_specified() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("www.example.com", HTTP_PORT));
    }

    #[test]
    fn specifying_a_port_in_host_header() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(host, Host::new("www.example.com", 8080));
    }

    #[test]
    fn specifying_a_non_numeric_port_in_host_header() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com:nannan\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data);

        assert_eq!(host, None);
    }

    #[test]
    fn specifying_a_missing_port_in_host_header() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com:\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data);

        assert_eq!(host, None);
    }

    #[test]
    fn is_connect_true_when_method_is_connect() {
        let data = b"CONNECT server.example.com:80 HTTP/1.1\r\nHost: server.example.com:80\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=\r\n\r\n";

        assert!(HttpProtocolPack::is_connect(data));
    }

    #[test]
    fn is_connect_false_when_message_has_message_other_than_connect() {
        let data = b"GET server.example.com:80 HTTP/1.1\r\nHost: server.example.com:80\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=\r\n\r\n";

        assert!(!HttpProtocolPack::is_connect(data));
    }

    #[test]
    fn is_connect_false_when_there_is_no_space_after_the_method() {
        let data = b"CONNECTX";
        assert!(!HttpProtocolPack::is_connect(data));
    }

    #[test]
    fn describe_packet_works_on_get_request_with_header_host() {
        let data =
            PlainData::new(b"GET /index.html?item=booga HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
        let subject = HttpProtocolPack {};

        let result = subject.describe_packet(&data);

        assert_eq!(
            result,
            "HTTP/1.1 GET request to www.example.com/index.html?item=booga"
        );
    }

    #[test]
    fn describe_packet_works_on_post_request_with_url_host() {
        let data = PlainData::new(
            b"POST www.example.com/person/1234 HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        );
        let subject = HttpProtocolPack {};

        let result = subject.describe_packet(&data);

        assert_eq!(
            result,
            "HTTP/1.1 POST request to www.example.com/person/1234"
        );
    }

    #[test]
    fn describe_packet_works_on_unexpected_request_with_unspecified_host() {
        let data = PlainData::new(b"BOOGA /person/1234 HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}");
        let subject = HttpProtocolPack {};

        let result = subject.describe_packet(&data);

        assert_eq!(
            result,
            "HTTP/1.1 BOOGA request to unknown host: /person/1234"
        );
    }

    #[test]
    fn describe_packet_works_on_malformed_request() {
        let data = PlainData::new(b"Fourscore_and_seven_years_ago_our_fathers_brought_forth_on_this_continent_a_new_nation,_conceived_in_liberty_and_dedicated_to_the_proposition_that_all_men_are_created_equal.");
        let subject = HttpProtocolPack {};

        let result = subject.describe_packet(&data);

        assert_eq!(
            result,
            "Malformed HTTP request: 'Fourscore_and_seven_years_ago_our_fathers_brought_'..."
        );
    }

    #[test]
    fn describe_packet_works_on_200_response() {
        let data =
            PlainData::new(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>");
        let subject = HttpProtocolPack {};

        let result = subject.describe_packet(&data);

        assert_eq!(result, "HTTP/1.1 response with status 200 OK");
    }

    #[test]
    fn describe_packet_works_on_malformed_response() {
        let data = PlainData::new(b"HTTP/Fourscore_and_seven_years_ago_our_fathers_brought_forth_on_this_continent_a_new_nation,_conceived_in_liberty_and_dedicated_to_the_proposition_that_all_men_are_created_equal.");
        let subject = HttpProtocolPack {};

        let result = subject.describe_packet(&data);

        assert_eq!(
            result,
            "Malformed HTTP response: 'HTTP/Fourscore_and_seven_years_ago_our_fathers_bro'..."
        );
    }
}
