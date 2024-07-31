// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crossbeam_channel::{unbounded, Receiver};
use simple_server::{Request, Server};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::ops::Add;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub struct TestServer {
    port: u16,
    rx: Receiver<Request<Vec<u8>>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl TestServer {
    pub fn start(port: u16, bodies: Vec<Vec<u8>>) -> Self {
        std::env::set_var("SIMPLESERVER_THREADS", "1");
        let (tx, rx) = unbounded();
        let _ = thread::spawn(move || {
            let bodies_arc = Arc::new(Mutex::new(bodies));
            Server::new(move |req, mut rsp| {
                if req.headers().get("X-Quit").is_some() {
                    panic!("Server stop requested");
                }
                tx.send(req).unwrap();
                let body = bodies_arc.lock().unwrap().remove(0);
                let result = rsp.body(body);
                Ok(result?)
            })
            .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });
        let deadline = Instant::now().add(Duration::from_secs(5));
        loop {
            thread::sleep(Duration::from_millis(10));
            match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)) {
                Ok(_) => break,
                Err(e) => eprintln!("No: {:?}", e),
            }
            if Instant::now().gt(&deadline) {
                panic!("TestServer still not started after 5sec");
            }
        }
        TestServer { port, rx }
    }

    pub fn requests_so_far(&self) -> Vec<Request<Vec<u8>>> {
        let mut requests = vec![];
        while let Ok(request) = self.rx.try_recv() {
            requests.push(request);
        }
        return requests;
    }

    fn stop(&mut self) {
        let mut stream =
            match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)) {
                Ok(s) => s,
                Err(_) => return,
            };
        stream
            .write(b"DELETE /irrelevant.htm HTTP/1.1\r\nX-Quit: Yes")
            .unwrap();
    }
}
