// Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use simple_server::{Method, Request, ResponseBuilder, ResponseResult, Server};
use serde::{Deserialize, Serialize};
use masq_lib::utils::localhost;

struct MBCSBuilder {
    port: u16,
    response_batch: Option<Vec<String>>,
    responses: Vec<String>
}

impl MBCSBuilder {
    pub fn new (port: u16) -> Self {
        Self {
            port,
            response_batch: None,
            responses: vec![],
        }
    }

    pub fn begin_batch (mut self) -> Self {
        if self.response_batch.is_some() {panic! ("Cannot nest response batches")}
        self.response_batch = Some (vec![]);
        self
    }

    pub fn end_batch (mut self) -> Self {
        let batch_contents = self.response_batch.take().unwrap();
        self.responses.push (format! ("[{}]", batch_contents.join (", ")));
        self
    }

    pub fn response<R> (mut self, result: R, id: u64) -> Self where R: Serialize {
        let result = serde_json::to_string (&result).unwrap();
        let body = format! (r#"{{"jsonrpc": "2.0", "result": {}, "id": {}}}"#, result, id);
        self.responses.push (body);
        self
    }

    pub fn error<D> (mut self, code: u64, message: &str, data: Option<D>) -> Self where D: Serialize {
        let data_str = match data.map (|d| serde_json::to_string (&d).unwrap()) {
            None => "".to_string(),
            Some (json) => format! (r#", "data": {}"#, json)
        };
        let body = format! (r#"{{"jsonrpc": "2.0", "error": {{"code": {}, "message": "{}"{}}}}}"#, code, message, data_str);
        self.responses.push (body);
        self
    }

    pub fn start(self) -> MockBlockchainClientServer {
        let requests = Arc::new (Mutex::new (vec![]));
        let responses = Arc::new (Mutex::new (self.responses));
        let handler = MockBlockchainClientServer::make_handler(requests.clone(), responses);
        let server = Server::new (handler);
        let join_handle = thread::spawn (move || {server.listen ("127.0.0.1", format! ("{}", self.port).as_str())});
        MockBlockchainClientServer {
            port: self.port,
            join_handle_opt: Some(join_handle),
            requests,
        }
    }
}

struct MockBlockchainClientServer {
    port: u16,
    join_handle_opt: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<Request<Vec<u8>>>>>,
}

impl Drop for MockBlockchainClientServer {
    fn drop(&mut self) {
        let mut client = TcpStream::connect(SocketAddr::new(localhost(), self.port)).unwrap();
        let request = b"DELETE /stop_server HTTP/1.1\n\n";
        client.write_all(request.as_slice()).unwrap();
        let _result = self.join_handle_opt.take().unwrap().join();
        // assert_eq! (format! ("{:?}", result.err()), "Server killed".to_string());
    }
}

impl MockBlockchainClientServer {
    pub fn builder(port: u16) -> MBCSBuilder {
        MBCSBuilder::new (port)
    }

    pub fn requests (&self) -> Vec<String> {
        let mut from = self.requests.lock().unwrap();
        let mut to = vec![];
        while !from.is_empty() {
            to.push (String::from_utf8(from.remove (0).body().clone()).unwrap())
        }
        to
    }

    fn make_handler (
        requests_arc: Arc<Mutex<Vec<Request<Vec<u8>>>>>,
        responses_arc: Arc<Mutex<Vec<String>>>
    ) -> impl Fn(Request<Vec<u8>>, ResponseBuilder) -> ResponseResult + 'static + Send + Sync {
        move |request: Request<Vec<u8>>, mut builder: ResponseBuilder| {
            if request.method() == &Method::DELETE {
                panic! ("Server killed")
            }
            let mut requests = requests_arc.lock().unwrap();
            let mut responses = responses_arc.lock().unwrap();
eprintln! ("Handler received request: {}", String::from_utf8(request.body().clone()).unwrap());
            requests.push (request);
            let body = responses.remove (0);
            let response = builder
                .status (200)
                .header ("Content-Type", "application-json")
                .body (body.as_bytes().to_vec())
                .unwrap();
eprintln! ("Handler sending response: {}", String::from_utf8(response.body().clone()).unwrap());
            Ok (response)
        }
    }
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
    fn works () {
        let port = find_free_port();
        let subject = MockBlockchainClientServer::builder (port)
            // .begin_batch()
            // .response (1234u64, 40)
            // .response ("Booga".to_string(), 41)
            // .end_batch()
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
//
//         let request = make_post (r#"{"jsonrpc": "2.0", "method": "first", "params": ["biddle", "de", "bee"], "id": 40}"#);
// eprintln! ("Test sending request: {}", String::from_utf8(request.clone()).unwrap());
//         client.write_all(request.as_slice()).unwrap();
//
//         let (response_header, response_body) = receive_response (&mut client);
//         verify_response_header(&response_header, &response_body);
//         assert_eq! (&response_body, r#"[{"jsonrpc": "2.0", "result": 1234, "id": 40}, {"jsonrpc": "2.0", "result": "Booga", "id": 41}]"#);

        let request = make_post (r#"{"jsonrpc": "2.0", "method": "second", "id": 42}"#);
eprintln! ("Test sending request: {}", String::from_utf8(request.clone()).unwrap());
        client.write_all(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response (&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq! (&response_body, r#"{"jsonrpc": "2.0", "result": {"name":"Billy","age":15}, "id": 42}"#);

        let request = make_post (r#"{"jsonrpc": "2.0", "method": "third", "id": 42}"#);
eprintln! ("Test sending request: {}", String::from_utf8(request.clone()).unwrap());
        client.write_all(request.as_slice()).unwrap();

        let (response_header, response_body) = receive_response (&mut client);
        verify_response_header(&response_header, &response_body);
        assert_eq! (&response_body, r#"{"jsonrpc": "2.0", "error": {"code": 4321, "message": "Taxation is theft!", "data": {"name": "Stanley", "age": 37}}"#);

        let requests = subject.requests();
        assert_eq! (requests, vec! [
            r#"[{"jsonrpc": "2.0", "result": 1234, "id": 40}, {"jsonrpc": "2.0", "result": "Booga", "id": 41}]"#.to_string(),
            r#"{"jsonrpc": "2.0", "method": "second", "id": 42}"#.to_string(),
            r#"{"jsonrpc": "2.0", "method": "third", "id": 42}"#.to_string(),
        ])
    }

    fn receive_response (client: &mut TcpStream) -> (String, String) {
        let mut buffer = [0u8; 1024];
        let mut response_str = String::new();
        let mut expected_length_opt = None;
        let return_char = char::from_u32 (13).unwrap();
        let length_re = Regex::new(r"[Cc]ontent-[Ll]ength: *(\d+)").unwrap();
        let deadline = Instant::now().add (Duration::from_secs(10));
eprintln! ("Test awaiting response");
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
eprintln! ("Test received response: {}", parts[1]);
        (parts[0].to_string(), parts[1].to_string())
    }

    fn verify_response_header (response_header: &str, response_body: &str) {
        assert_eq! (response_header.contains ("HTTP/1.1 200 OK\n"), true, "{}", response_header);
        assert_eq! (response_header.contains ("content-type: application-json"), true, "{}", response_header);
        assert_eq! (response_header.contains (format! ("content-length: {}\n", response_body.len()).as_str()), true, "{}", response_header);
    }

    fn make_post (body: &str) -> Vec<u8> {
        format! ("POST /biddle HTTP/1.1\nContent-Type: application-json\nContent-Length: {}\n\n{}", body.len(), body).into_bytes()
    }
}