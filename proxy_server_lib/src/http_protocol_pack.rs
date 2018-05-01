use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::cryptde::PlainData;
use sub_lib::utils::index_of;
use protocol_pack::ProtocolPack;

pub  struct HttpProtocolPack {}

impl ProtocolPack for HttpProtocolPack {
    fn proxy_protocol(&self) -> ProxyProtocol {ProxyProtocol::HTTP}

    fn find_host_name(&self, data: &PlainData) -> Option<String> {
        match HttpProtocolPack::find_header_host_name (&data.data[..]) {
            Some (string) => return Some (string),
            None => ()
        }
        HttpProtocolPack::find_url_host_name (&data.data[..])
    }
}

impl HttpProtocolPack {

    fn find_header_host_name (data: &[u8]) -> Option<String> {
        let idx = index_of (data, &b"\r\n\r\n"[..])?;
        let headers = &data[0..idx + 2];
        let needle = b"\r\nHost: ";
        let begin = index_of (&headers, &needle[..])? + needle.len ();
        let end = index_of (&headers[begin..], &b"\r\n"[..])? + begin;
        let hostname_u8s = &headers[begin..end];
        match String::from_utf8 (Vec::from (hostname_u8s)) {
            Ok(result) => Some(result),
            Err(_) => None
        }
    }

    fn find_url_host_name (data: &[u8]) -> Option<String> {
        let idx = index_of (data, &b"\r\n"[..])?;
        let first_line = &data[0..idx];
        let (index, prefix) = HttpProtocolPack::index_of_multi (first_line, vec! (&b" http://"[..], &b" https://"[..]))?;
        let begin = index + prefix.len ();
        let second_space_index = index_of (&data[begin..], &b" "[..])? + begin;
        let index = match HttpProtocolPack::index_of_multi (&first_line[begin..second_space_index], vec! (&b":"[..], &b"/"[..])) {
            Some ((index, _)) => index,
            None => second_space_index - begin
        };
        let end = begin + index;
        let hostname_u8s = &first_line[begin..end];
        match String::from_utf8 (Vec::from (hostname_u8s)) {
            Ok(result) => Some(result),
            Err(_) => None
        }
    }

    fn index_of_multi<'a> (haystack: &'a [u8], needles: Vec<&'a [u8]>) -> Option<(usize, &'a [u8])> {
        for needle in needles {
            match index_of (haystack, needle) {
                Some (index) => return Some ((index, needle)),
                None => ()
            }
        }
        None
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn knows_its_protocol () {
        let result = HttpProtocolPack{}.proxy_protocol();

        assert_eq! (result, ProxyProtocol::HTTP);
    }

    #[test]
    fn returns_none_if_no_double_crlf () {
        let data = PlainData::new (b"no\r\ndouble\r\ncrlf\r\n");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, None);
    }

    #[test]
    fn returns_none_if_double_crlf_but_no_hostname () {
        let data = PlainData::new (b"GET /nohostname.html HTTP/1.1\r\nContent-Length: 8\r\n\r\nbodybody");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, None);
    }

    #[test]
    fn returns_none_if_hostname_doesnt_end_properly () {
        let data = PlainData::new (b"POST /nohostname.html HTTP/1.1\r\nHost: improperly.ended");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, None);
    }

    #[test]
    fn returns_host_name_from_header_if_both_exist () {
        let data = PlainData::new (b"OPTIONS http://top.host.com/index.html HTTP/1.1\r\nHost: header.host.com\r\n\r\nbodybody");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, Some (String::from ("header.host.com")));
    }

    #[test]
    fn returns_host_name_from_http_url_if_header_doesnt_exist () {
        let data = PlainData::new (b"DELETE http://top.host.com/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, Some (String::from ("top.host.com")));
    }

    #[test]
    fn returns_host_name_from_https_url_if_header_doesnt_exist () {
        let data = PlainData::new (b"PUT https://top.host.com/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, Some (String::from ("top.host.com")));
    }

    #[test]
    fn returns_host_name_even_when_no_path () {
        let data = PlainData::new (b"PROXY http://top.host.com HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, Some (String::from ("top.host.com")));
    }

    #[test]
    fn returns_host_name_when_port_is_present () {
        let data = PlainData::new (b"HEAD http://top.host.com:8080/index.html HTTP/1.1\r\nContent-Length: 23\r\n\r\nHost: body.host.com\r\n\r\n");

        let result = HttpProtocolPack{}.find_host_name (&data);

        assert_eq! (result, Some (String::from ("top.host.com")));
    }
}
