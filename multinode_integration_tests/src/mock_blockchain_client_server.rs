// Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use masq_lib::utils::localhost;

struct MBCSBuilder {
    port: u16,
    response_batch_opt: Option<Vec<String>>,
    responses: Vec<String>
}

impl MBCSBuilder {
    pub fn new (port: u16) -> Self {
        Self {
            port,
            response_batch_opt: None,
            responses: vec![],
        }
    }

    pub fn begin_batch (mut self) -> Self {
        if self.response_batch_opt.is_some() {panic! ("Cannot nest response batches")}
        self.response_batch_opt = Some (vec![]);
        self
    }

    pub fn end_batch (mut self) -> Self {
        let batch_contents = self.response_batch_opt.take().unwrap();
        self.responses.push (format! ("[{}]", batch_contents.join (", ")));
        self
    }

    pub fn response<R> (self, result: R, id: u64) -> Self where R: Serialize {
        let result = serde_json::to_string (&result).unwrap();
        let body = format! (r#"{{"jsonrpc": "2.0", "result": {}, "id": {}}}"#, result, id);
        self.store_response_string(body)
    }

    pub fn error<D> (self, code: u64, message: &str, data: Option<D>) -> Self where D: Serialize {
        let data_str = match data.map (|d| serde_json::to_string (&d).unwrap()) {
            None => "".to_string(),
            Some (json) => format! (r#", "data": {}"#, json)
        };
        let body = format! (r#"{{"jsonrpc": "2.0", "error": {{"code": {}, "message": "{}"{}}}}}"#, code, message, data_str);
        self.store_response_string(body)
    }

    pub fn start(self) -> MockBlockchainClientServer {
        let requests = Arc::new (Mutex::new (vec![]));
        let mut server = MockBlockchainClientServer {
            port: self.port,
            join_handle_opt: None,
            requests_arc: requests,
            responses: self.responses,
        };
        server.join_handle_opt = Some (server.start());
        server
    }

    fn store_response_string (mut self, response_string: String) -> Self {
        match self.response_batch_opt.as_mut() {
            Some (response_batch) => response_batch.push (response_string),
            None => self.responses.push (response_string)
        }
        self
    }
}

const MBCS_SENTINEL: &str = "---stop-server---";

struct MockBlockchainClientServer {
    port: u16,
    join_handle_opt: Option<JoinHandle<()>>,
    requests_arc: Arc<Mutex<Vec<String>>>,
    responses: Vec<String>,
}

impl Drop for MockBlockchainClientServer {
    fn drop(&mut self) {
        let mut client = match TcpStream::connect(SocketAddr::new(localhost(), self.port)) {
            Ok (c) => c,
            Err (_) => return, // can't connect, already down, mission complete
        };
        let request = MBCS_SENTINEL.as_bytes();
        client.write_all(request).unwrap();
        let _result = self.join_handle_opt.take().unwrap().join();
        // assert_eq! (format! ("{:?}", _result.err()), "Server stopped".to_string());
    }
}

impl MockBlockchainClientServer {
    pub fn builder(port: u16) -> MBCSBuilder {
        MBCSBuilder::new (port)
    }

    pub fn requests (&self) -> Vec<String> {
        self.requests_arc.lock().unwrap().drain(..).collect()
    }

    pub fn start (&mut self) -> JoinHandle<()> {
        let listener = TcpListener::bind (SocketAddr::new (localhost(), self.port)).unwrap();
        let requests_arc = self.requests_arc.clone();
        let mut responses: Vec<String> = self.responses.drain(..).collect();
        thread::spawn (move || {
            let (conn, _) = listener.accept().unwrap();
            drop (listener);
            conn.set_nonblocking(false).unwrap();
            conn.set_read_timeout (Some (Duration::from_secs(10))).unwrap();
            let mut conn_state = ConnectionState {
                conn,
                receive_buffer: [0u8; 16384],
                receive_buffer_len: 0,
            };
            loop {
                let body = match Self::receive_body (&mut conn_state) {
                    Some (s) if s.len() == 0 => break,
                    Some (s) => s,
                    None => continue,
                };
                if &body == MBCS_SENTINEL {
                    break;
                }
                {
                    let mut requests = requests_arc.lock().unwrap();
                    requests.push (body);
                }
                let response = responses.remove (0);
                Self::send_body (&mut conn_state, response);
            }
        })
    }

    fn receive_body (conn_state: &mut ConnectionState) -> Option<String> {
        let len = match conn_state.conn.read (&mut conn_state.receive_buffer) {
            Ok (n) => n,
            Err (e) if e.kind() == ErrorKind::Interrupted => return None,
            Err (e) if e.kind() == ErrorKind::TimedOut => return None,
            Err (e) if e.kind() == ErrorKind::WouldBlock => return None,
            Err (e) => panic! ("{:?}", e),
        };
        conn_state.receive_buffer_len = len;
        Some (String::from_utf8(conn_state.receive_buffer[0..conn_state.receive_buffer_len].to_vec()).unwrap())

        // let length_re = Regex::new(r"[Cc]ontent-[Ll]ength: *(\d+)").unwrap();
        // let body_length_str = length_re.captures(&http).unwrap().get(1).unwrap();
        // let body_length = body_length_str.as_str().parse::<usize>().unwrap();
    }

    fn send_body (conn_state: &mut ConnectionState, response: String) {
        let http = format! ("HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: {}\n\n{}",
            response.len(), response);
        let _ = conn_state.conn.write_all (http.as_bytes()).unwrap();
    }
}

// enum ResponseStage {
//     PartialHeading {header_offset: usize},
//     ContentLength {header_offset: usize, content_length: usize},
//     PartialBody {header_offset: usize, content_offset: usize, content_length: usize},
//     Complete {header_offset: usize, content_offset: usize, content_length: usize},
// }

struct ConnectionState {
    conn: TcpStream,
    receive_buffer: [u8; 16384],
    receive_buffer_len: usize,
}

#[cfg (test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::ops::Add;
    use std::time::{Duration, Instant};
    use regex::Regex;
    use masq_lib::utils::{find_free_port, localhost};
    use super::*;


    #[derive(Serialize, Deserialize)]
    struct Person {
        pub name: String,
        pub age: u8,
    }

    #[test]
    fn receives_request_in_multiple_chunks() {
        todo! ();
    }

    #[test]
    fn parses_out_multiple_requests_from_single_chunk() {
        todo! ();
    }

    #[test]
    fn panics_if_given_a_request_without_a_content_length() {
        todo! ();
    }

    #[test]
    fn works () {
        let port = find_free_port();
        let subject = MockBlockchainClientServer::builder (port)
            .begin_batch()
            .response (1234u64, 40)
            .response ("Booga".to_string(), 41)
            .end_batch()
            .response (Person {name: "Billy".to_string(), age: 15}, 42)
            .error (4321, "Taxation is theft!", Some (Person {name: "Stanley".to_string(), age: 37}))
            .start();
        let connect = || {
            let deadline = Instant::now().add(Duration::from_secs(1));
            let addr = SocketAddr::new(localhost(), port);
            loop {
                thread::sleep (Duration::from_millis (100));
                match TcpStream::connect (&addr) {
                    Ok (client) => return client,
                    Err (e) => eprintln! ("Mock server not ready yet ({:?})", e)
                }
                if Instant::now ().gt (&deadline) {
                    panic! ("MockBlockchainClientServer never started");
                }
            }
        };
        let mut client = connect();
        client.set_nonblocking (false).unwrap();
        client.set_read_timeout (None).unwrap();

        let request = make_post (r#"{"jsonrpc": "2.0", "method": "first", "params": ["biddle", "de", "bee"], "id": 40}"#);
        client.write_all(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response (&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq! (&response_body, r#"[{"jsonrpc": "2.0", "result": 1234, "id": 40}, {"jsonrpc": "2.0", "result": "Booga", "id": 41}]"#);

        let request = make_post (r#"{"jsonrpc": "2.0", "method": "second", "id": 42}"#);
        client.write_all(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response (&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq! (&response_body, r#"{"jsonrpc": "2.0", "result": {"name":"Billy","age":15}, "id": 42}"#);

        let request = make_post (r#"{"jsonrpc": "2.0", "method": "third", "id": 42}"#);
        client.write_all(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response (&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq! (&response_body, r#"{"jsonrpc": "2.0", "error": {"code": 4321, "message": "Taxation is theft!", "data": {"name":"Stanley","age":37}}}"#);

        let requests = subject.requests();
        assert_eq! (requests, vec! [
            "POST /biddle HTTP/1.1\nContent-Type: application-json\nContent-Length: 82\n\n{\"jsonrpc\": \"2.0\", \"method\": \"first\", \"params\": [\"biddle\", \"de\", \"bee\"], \"id\": 40}".to_string(),
            "POST /biddle HTTP/1.1\nContent-Type: application-json\nContent-Length: 48\n\n{\"jsonrpc\": \"2.0\", \"method\": \"second\", \"id\": 42}".to_string(),
            "POST /biddle HTTP/1.1\nContent-Type: application-json\nContent-Length: 47\n\n{\"jsonrpc\": \"2.0\", \"method\": \"third\", \"id\": 42}".to_string(),
        ])
    }

    fn receive_response (client: &mut TcpStream) -> (String, String) {
        let mut buffer = [0u8; 1024];
        let mut response_str = String::new();
        let mut expected_length_opt = None;
        let return_char = char::from_u32 (13).unwrap();
        let length_re = Regex::new(r"[Cc]ontent-[Ll]ength: *(\d+)").unwrap();
        let deadline = Instant::now().add (Duration::from_secs(10));
        loop {
            let len = client.read (&mut buffer).unwrap();
            let string: String = String::from_utf8(buffer[0..len].to_vec()).unwrap()
                .chars()
                .filter (|c| c != &return_char)
                .collect();
            response_str.extend (string.chars());
            match response_str.find ("\n\n") {
                Some (index) => {
                    let body_length_str = length_re.captures(&response_str).unwrap().get(1).unwrap();
                    let body_length = body_length_str.as_str().parse::<usize>().unwrap();
                    expected_length_opt = Some (index + 2 + body_length);
                },
                None => ()
            }
            if let Some(expected_length) = expected_length_opt {
                if response_str.len() >= expected_length {break;}
            }
            if Instant::now().gt (&deadline) {
                panic! ("Timed out waiting for response from server");
            }
            thread::sleep (Duration::from_millis(100));
        }
        let parts = response_str.splitn (2, "\n\n").collect::<Vec<&str>>();
        (parts[0].to_string(), parts[1].to_string())
    }

    fn verify_response_header (response_header: &str, response_body: &str) {
        assert_eq! (response_header.contains ("HTTP/1.1 200 OK\n"), true, "{}", response_header);
        assert_eq! (response_header.contains ("Content-Type: application/json"), true, "{}", response_header);
        assert_eq! (response_header.contains (format! ("Content-Length: {}", response_body.len()).as_str()), true, "{}", response_header);
    }

    fn make_post (body: &str) -> Vec<u8> {
        format! ("POST /biddle HTTP/1.1\nContent-Type: application-json\nContent-Length: {}\n\n{}", body.len(), body).into_bytes()
    }
}