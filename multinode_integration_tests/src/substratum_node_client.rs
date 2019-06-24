// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::utils;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

pub struct SubstratumNodeClient {
    stream: TcpStream,
    timeout: Duration,
}

impl SubstratumNodeClient {
    pub fn new(socket_addr: SocketAddr) -> SubstratumNodeClient {
        let stream = TcpStream::connect(&socket_addr)
            .expect(format!("Connecting to {}", socket_addr).as_str());
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("Setting read timeout to 250ms");

        SubstratumNodeClient {
            stream,
            timeout: Duration::from_secs(1),
        }
    }

    pub fn get_stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout
    }

    pub fn send_chunk(&mut self, chunk: &[u8]) {
        utils::send_chunk(&mut self.stream, chunk)
    }

    pub fn wait_for_chunk(&mut self) -> Vec<u8> {
        match utils::wait_for_chunk(&mut self.stream, &self.timeout) {
            Ok(output) => output,
            Err(e) => panic!("Couldn't read chunk: {:?}", e),
        }
    }

    pub fn wait_for_shutdown(&mut self) {
        match utils::wait_for_shutdown(&mut self.stream, &self.timeout) {
            Ok(()) => (),
            Err(e) => panic!("Stream never shut down: {:?}", e),
        }
    }

    pub fn shutdown(&mut self) {
        self.stream.shutdown(Shutdown::Both).expect("Shutting down");
    }
}
