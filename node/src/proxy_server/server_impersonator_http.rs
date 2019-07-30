// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::ServerImpersonator;
use crate::sub_lib::cryptde::PublicKey;

pub struct ServerImpersonatorHttp {}

impl ServerImpersonator for ServerImpersonatorHttp {
    fn route_query_failure_response(&self, server_name: &str) -> Vec<u8> {
        ServerImpersonatorHttp::make_error_response(
            503,
            "Routing Problem",
            format!("Can't find a route to {}", server_name).as_str(),
            format!(
                "Substratum can't find a route through the Network yet to a Node that knows \
                 where to find {}. Maybe later enough will be known about the Network to \
                 find that Node, but we can't guarantee it. We're sorry.",
                server_name
            )
            .as_str(),
        )
    }

    fn dns_resolution_failure_response(
        &self,
        exit_key: &PublicKey,
        server_name_opt: Option<String>,
    ) -> Vec<u8> {
        let (server_name, quoted_server_name) = match &server_name_opt {
            Some(name) => (name.clone(), format!("\"{}\"", name)),
            None => ("<unspecified>".to_string(), "<unspecified>".to_string()),
        };
        ServerImpersonatorHttp::make_error_response(
            503,
            "DNS Resolution Problem",
            &format!("Exit Node couldn't resolve {}", quoted_server_name),
            &format!("We chose the exit Node {} for your request to {}; but when it asked \
        its DNS server to look up the IP address for {}, it wasn't found. If {} exists, \
        it will need to be looked up by a different exit Node. We've deprioritized this exit Node. \
        Reload the page, and we'll try to find another.",
                     exit_key, server_name, server_name, server_name),
        )
    }

    fn consuming_wallet_absent(&self) -> Vec<u8> {
        ServerImpersonatorHttp::make_error_response(
            402,
            "Consuming Wallet Required",
            "Can't consume without wallet to pay from",
            "You're trying to consume routing and exit services from other Nodes, but you haven't \
            specified a consuming wallet from which your Node can pay the bills you're about to incur. \
            Set up a funded consuming wallet and try again.",
        )
    }
}

impl ServerImpersonatorHttp {
    fn make_error_page(status: u16, title: &str, subtitle: &str, content: &str) -> String {
        let html = String::from(ERROR_TEMPLATE);
        html.replace("{status}", format!("{}", status).as_str())
            .replace("{title}", title)
            .replace("{subtitle}", subtitle)
            .replace("{content}", content)
    }

    fn make_error_response(status: u16, title: &str, subtitle: &str, content: &str) -> Vec<u8> {
        let html = ServerImpersonatorHttp::make_error_page(status, title, subtitle, content);
        let http = String::from(HTTP_RESPONSE_TEMPLATE);
        http.replace("{status}", format!("{}", status).as_str())
            .replace("{length}", format!("{}", html.len()).as_str())
            .replace("{body}", html.as_str())
            .as_bytes()
            .to_vec()
    }
}

const ERROR_TEMPLATE: &str = "<html>\n\
                              <body>\n\
                              <h1>Error {status}</h1>\n\
                              <h2>Title: {title}</h2>\n\
                              <h3>Subtitle: {subtitle}</h3>\n\
                              <p>{content}</p>\n\
                              </body>\n\
                              </html>\n";

const HTTP_RESPONSE_TEMPLATE: &str = "HTTP/1.1 {status} Routing Error\r\n\
                                      Content-Type: text/html\r\n\
                                      Content-Length: {length}\r\n\
                                      \r\n\
                                      {body}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_appropriate_error_page() {
        let result = ServerImpersonatorHttp::make_error_page(
            503,
            "I'm a title",
            "I'm a subtitle",
            "and I'm content",
        );

        assert_eq!(result.contains("<h1>Error 503</h1>"), true, "{}", result);
        assert_eq!(
            result.contains("<h2>Title: I'm a title</h2>"),
            true,
            "{}",
            result
        );
        assert_eq!(
            result.contains("<h3>Subtitle: I'm a subtitle</h3>"),
            true,
            "{}",
            result
        );
        assert_eq!(
            result.contains("<p>and I'm content</p>"),
            true,
            "{}",
            result
        );
    }

    #[test]
    fn creates_appropriate_error_response() {
        let error_page = ServerImpersonatorHttp::make_error_page(
            503,
            "I'm a title",
            "I'm a subtitle",
            "and I'm content",
        );

        let result = ServerImpersonatorHttp::make_error_response(
            503,
            "I'm a title",
            "I'm a subtitle",
            "and I'm content",
        );

        let result_string = String::from_utf8(result).unwrap();
        assert_eq!(
            result_string.contains("HTTP/1.1 503 Routing Error"),
            true,
            "{}",
            result_string
        );
        assert_eq!(
            result_string.contains(format!("Content-Length: {}", error_page.len()).as_str()),
            true,
            "{}",
            result_string
        );
        assert_eq!(
            result_string.contains("<p>and I'm content</p>"),
            true,
            "{}",
            result_string
        );
    }

    #[test]
    fn route_query_failure_response_produces_expected_error_page() {
        let subject = ServerImpersonatorHttp {};

        let result = subject.route_query_failure_response("server.com");

        let expected = ServerImpersonatorHttp::make_error_response(
            503,
            "Routing Problem",
            "Can't find a route to server.com",
            "Substratum can't find a route through the Network yet to a Node that knows \
             where to find server.com. Maybe later enough will be known about the Network to \
             find that Node, but we can't guarantee it. We're sorry.",
        );
        assert_eq!(expected, result);
    }

    #[test]
    fn dns_resolution_failure_response_with_server_name_produces_expected_error_page() {
        let subject = ServerImpersonatorHttp {};

        let result = subject.dns_resolution_failure_response(
            &PublicKey::new(&b"exit"[..]),
            Some("server.com".to_string()),
        );

        let expected = ServerImpersonatorHttp::make_error_response(
            503,
            "DNS Resolution Problem",
            "Exit Node couldn't resolve \"server.com\"",
            "We chose the exit Node ZXhpdA for your request to server.com; but when it asked its DNS server \
            to look up the IP address for server.com, it wasn't found. If server.com exists, \
            it will need to be looked up by a different exit Node. We've deprioritized this exit Node. \
            Reload the page, and we'll try to find another.",
        );
        assert_eq!(expected, result);
    }

    #[test]
    fn dns_resolution_failure_response_without_server_name_produces_expected_error_page() {
        let subject = ServerImpersonatorHttp {};

        let result = subject.dns_resolution_failure_response(&PublicKey::new(&b"exit"[..]), None);

        let expected = ServerImpersonatorHttp::make_error_response(
            503,
            "DNS Resolution Problem",
            "Exit Node couldn't resolve <unspecified>",
            "We chose the exit Node ZXhpdA for your request to <unspecified>; but when it asked its DNS server \
            to look up the IP address for <unspecified>, it wasn't found. If <unspecified> exists, \
            it will need to be looked up by a different exit Node. We've deprioritized this exit Node. \
            Reload the page, and we'll try to find another.",
        );
        assert_eq!(expected, result);
    }

    #[test]
    fn consuming_wallet_absent_response_produces_expected_error_page() {
        let subject = ServerImpersonatorHttp {};

        let result = subject.consuming_wallet_absent();

        let expected = ServerImpersonatorHttp::make_error_response(
            402,
            "Consuming Wallet Required",
            "Can't consume without wallet to pay from",
            "You're trying to consume routing and exit services from other Nodes, but you haven't \
            specified a consuming wallet from which your Node can pay the bills you're about to incur. \
            Set up a funded consuming wallet and try again.",
        );
        assert_eq!(expected, result);
    }
}
