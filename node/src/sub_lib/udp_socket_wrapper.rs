// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::io;
use std::marker::Send;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::prelude::Async;

pub trait UdpSocketWrapperTrait: Sync + Send {
    fn bind(&mut self, addr: SocketAddr) -> io::Result<bool>;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<Async<(usize, SocketAddr)>, io::Error>;
    fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<Async<usize>, io::Error>;
}

#[derive(Default)]
pub struct UdpSocketWrapperReal {
    delegate: Option<UdpSocket>,
}

impl UdpSocketWrapperReal {
    pub fn new() -> Self {
        Self::default()
    }
}

impl UdpSocketWrapperTrait for UdpSocketWrapperReal {
    fn bind(&mut self, addr: SocketAddr) -> io::Result<bool> {
        let socket = UdpSocket::bind(&addr)?;
        self.delegate = Some(socket);
        Ok(true)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<Async<(usize, SocketAddr)>, io::Error> {
        match self.delegate {
            Some(ref mut socket) => socket.poll_recv_from(buf),
            None => panic!("call bind before recv_from"),
        }
    }

    fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<Async<usize>, io::Error> {
        match self.delegate {
            Some(ref mut socket) => socket.poll_send_to(buf, &addr),
            None => panic!("call bind before send_to"),
        }
    }
}
