// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub fn make_error_page(status: u16, title: &str, subtitle: &str, content: &str) -> String {
    let html = String::from(ERROR_TEMPLATE);
    html.replace("{status}", format!("{}", status).as_str())
        .replace("{title}", title)
        .replace("{subtitle}", subtitle)
        .replace("{content}", content)
}

pub fn make_error_response(status: u16, title: &str, subtitle: &str, content: &str) -> Vec<u8> {
    let html = make_error_page(status, title, subtitle, content);
    let http = String::from(HTTP_RESPONSE_TEMPLATE);
    http.replace("{status}", format!("{}", status).as_str())
        .replace("{length}", format!("{}", html.len()).as_str())
        .replace("{body}", html.as_str())
        .as_bytes()
        .to_vec()
}

const ERROR_TEMPLATE: &str = "<html>\n\
                              <body>\n\
                              <h1>Error {status}</h1>\n\
                              <h2>Title: {title}</h2>\n\
                              <h3>Subtitle: {subtitle}</h3>\n\
                              <p>{content}</p>\n\
                              <p>This will look much better after SC-378 is done</p>\n\
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
        let result = make_error_page(503, "I'm a title", "I'm a subtitle", "and I'm content");

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
        let error_page = make_error_page(503, "I'm a title", "I'm a subtitle", "and I'm content");

        let result = make_error_response(503, "I'm a title", "I'm a subtitle", "and I'm content");

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
}
