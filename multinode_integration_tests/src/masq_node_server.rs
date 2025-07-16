// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::masq_node_cluster::DockerHostSocketAddr;
use crate::utils;
use std::{io, thread};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;
use crossbeam_channel::{unbounded, Receiver, Sender};

pub struct MASQNodeServer {
    docker_host_addr: Option<DockerHostSocketAddr>,
    local_addr: SocketAddr,
    stream_opt: Option<TcpStream>,
}

impl MASQNodeServer {
    pub fn new(port: u16) -> MASQNodeServer {
        let dummy_listener = TcpListener::bind(DockerHostSocketAddr::new(port)).unwrap();
        let local_addr = dummy_listener.local_addr().unwrap();
        MASQNodeServer {
            docker_host_addr: Some(DockerHostSocketAddr::new(port)),
            local_addr,
            stream_opt: None,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn send_chunk(&mut self, chunk: &[u8]) {
        match &mut self.stream_opt {
            None => panic!("Can't send response until after requester connects"),
            Some(stream) => utils::send_chunk(stream, chunk),
        }
    }

    pub fn wait_for_chunk(&mut self, duration: Duration) -> Result<Vec<u8>, io::Error> {
        match &mut self.stream_opt {
            None => {
                let (tx, rx): (Sender<TcpStream>, Receiver<TcpStream>) = unbounded();
                let local_addr = self.docker_host_addr.take().unwrap();
                let listener = TcpListener::bind(local_addr).unwrap();
                thread::spawn(move || {
                    let (stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(250)))
                        .unwrap();
                    tx.send(stream).unwrap();
                });
                let stream = rx.recv_timeout(duration.clone()).unwrap();
                self.stream_opt = Some(stream);
                self.wait_for_chunk(duration)
            }
            Some(stream) => {
                utils::wait_for_chunk(stream, &duration)
            },
        }
    }

    pub fn shutdown(&self) {
        match &self.stream_opt {
            None => (),
            Some(stream) => match stream.shutdown(Shutdown::Both) {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to shut stream down: {} - continuing", e),
            },
        }
    }

    pub fn wait_for_shutdown(&mut self, timeout: Duration) {
        match utils::wait_for_shutdown(self.stream_opt.as_mut().unwrap(), &timeout) {
            Ok(()) => (),
            Err(e) => panic!("Stream never shut down: {:?}", e),
        }
    }
}
