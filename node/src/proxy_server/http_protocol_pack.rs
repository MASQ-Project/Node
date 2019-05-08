// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::{Host, ProtocolPack, ServerImpersonator};
use crate::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::proxy_server::ProxyProtocol;
use crate::sub_lib::utils::index_of;

pub struct HttpProtocolPack {}

impl ProtocolPack for HttpProtocolPack {
    fn proxy_protocol(&self) -> ProxyProtocol {
        ProxyProtocol::HTTP
    }

    fn standard_port(&self) -> u16 {
        80
    }

    fn find_host(&self, data: &PlainData) -> Option<Host> {
        match HttpProtocolPack::find_url_host(data.as_slice()) {
            Some(host) => Some(host),
            None => HttpProtocolPack::find_header_host(data.as_slice()),
        }
    }

    fn server_impersonator(&self) -> Box<ServerImpersonator> {
        Box::new(ServerImpersonatorHttp {})
    }
}

impl HttpProtocolPack {
    fn find_url_host(data: &[u8]) -> Option<Host> {
        let idx = index_of(data, &b"\r\n"[..])?;
        let first_line = &data[0..idx];
        let (index, prefix) =
            HttpProtocolPack::find_first(first_line, vec![&b" http://"[..], &b" https://"[..]])?;
        let path_begin = index + prefix.len();
        let path_end = index_of(&data[path_begin..], &b" "[..])? + path_begin;
        let path = match String::from_utf8(Vec::from(&data[path_begin..path_end])) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let mut path_parts: Vec<&str> = path.split("/").collect();
        let host_name_and_port = path_parts.remove(0);
        Self::host_from_host_name_and_port(host_name_and_port)
    }

    fn find_header_host(data: &[u8]) -> Option<Host> {
        let idx = index_of(data, &b"\r\n\r\n"[..])?;
        let headers = &data[0..idx + 2];
        let needle = b"\r\nHost: ";
        let begin = index_of(&headers, &needle[..])? + needle.len();
        let host_header_value =
            &headers[begin..(index_of(&headers[begin..], &b"\r\n"[..])? + begin)];
        let host_and_port = match String::from_utf8(Vec::from(host_header_value)) {
            Err(_) => return None,
            Ok(s) => s,
        };
        Self::host_from_host_name_and_port(&host_and_port)
    }

    fn host_from_host_name_and_port(host_and_port: &str) -> Option<Host> {
        let mut parts: Vec<&str> = host_and_port.split(":").collect();
        match parts.len() {
            1 => Some(Host {
                name: parts.remove(0).to_string(),
                port: None,
            }),
            2 => Some(Host {
                name: parts.remove(0).to_string(),
                port: Self::port_from_string(parts.remove(0).to_string()),
            }),
            _ => None,
        }
    }

    fn port_from_string(port_str: String) -> Option<u16> {
        match port_str.parse::<u16>() {
            Err(_) => None,
            Ok(port) => Some(port),
        }
    }

    fn find_first<'a>(haystack: &'a [u8], needles: Vec<&'a [u8]>) -> Option<(usize, &'a [u8])> {
        for needle in needles {
            match index_of(haystack, needle) {
                Some(index) => return Some((index, needle)),
                None => (),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_its_protocol() {
        let result = HttpProtocolPack {}.proxy_protocol();

        assert_eq!(ProxyProtocol::HTTP, result);
    }

    #[test]
    fn knows_its_standard_port() {
        let result = HttpProtocolPack {}.standard_port();

        assert_eq!(80, result);
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

        assert_eq!(String::from("header.host.com"), host.name);
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

        assert_eq!(String::from("192.168.1.230"), host.name);
        assert_eq!(None, host.port);
    }

    #[test]
    fn returns_host_name_and_port_from_url_if_both_exist() {
        let data = PlainData::new (b"OPTIONS http://top.host.com:1234/index.html HTTP/1.1\r\nHost: header.host.com:5432\r\n\r\nbodybody");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
        assert_eq!(Some(1234), host.port);
    }

    #[test]
    fn returns_host_name_from_http_url_if_header_doesnt_exist() {
        let data = PlainData::new (b"DELETE http://top.host.com/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
    }

    #[test]
    fn returns_host_name_from_https_url_if_header_doesnt_exist() {
        let data = PlainData::new (b"PUT https://top.host.com/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
    }

    #[test]
    fn returns_host_name_even_when_no_path() {
        let data = PlainData::new (b"PROXY http://top.host.com HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
    }

    #[test]
    fn specifying_a_port_in_the_url() {
        let data = PlainData::new (b"HEAD http://top.host.com:8080/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
        assert_eq!(Some(8080), host.port);
    }

    #[test]
    fn specifying_two_colons_in_the_url() {
        let data = PlainData::new (b"HEAD http://top.host.com:8080:1234/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let result = HttpProtocolPack {}.find_host(&data);

        assert_eq!(None, result);
    }

    #[test]
    fn specifying_a_non_numeric_port_in_the_url() {
        let data = PlainData::new (b"HEAD http://top.host.com:nanan/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
        assert_eq!(None, host.port);
    }

    #[test]
    fn specifying_a_missing_port_in_the_url() {
        let data = PlainData::new (b"HEAD http://top.host.com:/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("top.host.com"), host.name);
        assert_eq!(None, host.port);
    }

    #[test]
    fn from_integration_test() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("www.example.com"), host.name);
    }

    #[test]
    fn explicit_port_is_none_if_it_was_not_specified() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("www.example.com"), host.name);
        assert_eq!(None, host.port);
    }

    #[test]
    fn specifying_a_port_in_host_header() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("www.example.com"), host.name);
        assert_eq!(Some(8080), host.port);
    }

    #[test]
    fn specifying_a_non_numeric_port_in_host_header() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com:nannan\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("www.example.com"), host.name);
        assert_eq!(None, host.port);
    }

    #[test]
    fn specifying_a_missing_port_in_host_header() {
        let data = PlainData::new(b"GET / HTTP/1.1\r\nHost: www.example.com:\r\n\r\n");

        let host = HttpProtocolPack {}.find_host(&data).unwrap();

        assert_eq!(String::from("www.example.com"), host.name);
        assert_eq!(None, host.port);
    }
}
