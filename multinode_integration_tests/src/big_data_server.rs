// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crossbeam_channel::{unbounded, Sender};
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::thread;
use std::time::Duration;

const CHUNK_SIZE: usize = 131072;

pub struct BigDataServer {
    tx: Sender<()>,
    local_addr: SocketAddr,
}

impl Drop for BigDataServer {
    fn drop(&mut self) {
        self.tx.send(()).unwrap();
    }
}

impl BigDataServer {
    pub fn start(
        socket_addr: &dyn ToSocketAddrs<Iter = std::vec::IntoIter<SocketAddr>>,
        size: usize,
    ) -> BigDataServer {
        let listener = TcpListener::bind(socket_addr).unwrap();
        let local_addr = listener.local_addr().unwrap();
        let (tx, rx) = unbounded_channel();
        thread::spawn(move || {
            let mut buf = [0u8; CHUNK_SIZE];
            loop {
                if rx.try_recv().is_ok() {
                    return;
                }
                match listener.accept() {
                    Err(e) => {
                        eprintln!("BigDataServer could not accept connection: {:?}", e);
                        continue;
                    }
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap();
                        loop {
                            if rx.try_recv().is_ok() {
                                return;
                            }
                            match stream.read(&mut buf) {
                                Err(e) => {
                                    eprintln!("BigDataServer could not read request: {:?}", e);
                                    break;
                                }
                                Ok(len) if len == 0 => break,
                                Ok(_) => {
                                    if rx.try_recv().is_ok() {
                                        return;
                                    }
                                    match stream.write(&Self::make_header(size)) {
                                        Ok(_) => eprintln!("BigDataServer sent response header"),
                                        Err(e) => {
                                            eprintln! ("BigDataServer could not send response header: {:?}", e);
                                            break;
                                        }
                                    };
                                    let mut bytes_remaining = size;
                                    while bytes_remaining > 0 {
                                        let len = if bytes_remaining > CHUNK_SIZE {
                                            CHUNK_SIZE
                                        } else {
                                            bytes_remaining
                                        };
                                        bytes_remaining -= len;
                                        match stream.write (&buf[0..len]) {
                                            Ok(_) => eprintln! ("BigDataServer sent {} worthless response bytes; {} remain", len, bytes_remaining),
                                            Err(e) => {
                                                eprintln! ("BigDataServer could not send response bytes: {:?}", e);
                                                break;
                                            }
                                        };
                                    }
                                }
                            };
                        }
                    }
                }
            }
        });
        thread::sleep(Duration::from_secs(1));
        BigDataServer { tx, local_addr }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn make_header(size: usize) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", size).into_bytes()
    }
}
