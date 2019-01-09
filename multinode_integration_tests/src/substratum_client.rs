// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::Instant;

pub struct SubstratumNodeClient {
    stream: TcpStream,
    timeout: Duration,
}

impl SubstratumNodeClient {
    pub fn new(socket_addr: SocketAddr) -> SubstratumNodeClient {
        let stream = TcpStream::connect(&socket_addr)
            .expect(format!("Connecting to {}", socket_addr).as_str());
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("Setting read timeout to 10ms");

        SubstratumNodeClient {
            stream,
            timeout: Duration::from_secs(60),
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout
    }

    pub fn send_chunk(&mut self, chunk: Vec<u8>) {
        self.stream
            .write(&chunk[..])
            .expect(format!("Writing {} bytes", chunk.len()).as_str());
    }

    pub fn wait_for_chunk(&mut self) -> Vec<u8> {
        let mut output: Vec<u8> = vec![];
        let mut buf: [u8; 65536] = [0; 65536];
        let mut begin = Instant::now();
        loop {
            let latency_so_far = Instant::now().duration_since(begin);
            if latency_so_far.ge(&self.timeout) {
                eprintln!("Timed out after waiting {:?} for new data", self.timeout);
                self.shutdown();
                return output;
            }

            match self.stream.read(&mut buf) {
                Ok(n) if n == buf.len() => {
                    begin = Instant::now();
                    output.extend(buf.iter())
                }
                Ok(_) => {
                    output.extend(buf.iter());
                    return output;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    eprintln!("Couldn't read chunk; waiting for 500ms to retry");
                    thread::sleep(Duration::from_millis(500))
                }
                Err(e) => panic!("Couldn't read chunk: {:?}", e),
            }
        }
    }

    pub fn shutdown(&mut self) {
        self.stream.shutdown(Shutdown::Both).expect("Shutting down");
    }
}
