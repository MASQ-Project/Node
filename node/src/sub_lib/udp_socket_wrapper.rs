// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::io;
use std::marker::Send;
use std::net::SocketAddr;
use tokio::net::{UdpSocket};

pub trait UdpSocketWrapperTrait: Sync + Send {
    fn bind(&mut self, addr: SocketAddr) -> io::Result<bool>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
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

    // pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.delegate {
            Some(ref mut socket) => socket.recv_from(buf),
            None => panic!("call bind before recv_from"),
        }
    }

    // pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match self.delegate {
            Some(ref mut socket) => socket.send_to(buf, addr),
            None => panic!("call bind before send_to"),
        }
    }
}
