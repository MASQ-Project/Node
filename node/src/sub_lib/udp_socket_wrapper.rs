// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use async_trait::async_trait;
use std::io;
use std::marker::Send;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[async_trait]
pub trait UdpSocketWrapperTrait: Sync + Send {
    // TODO: It appears that this bool is never used. It's only ever true, anyway.
    async fn bind(&mut self, addr: SocketAddr) -> io::Result<bool>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
}

// TODO: A wrapper with an Option<> delegate is embarrassing. This should be a combination of
// UdpSocketWrapperReal (with delegate: UdpSocket) and UdpSocketWrapperFactoryReal (with no delegate).
#[derive(Default)]
pub struct UdpSocketWrapperReal {
    delegate: Option<UdpSocket>,
}

impl UdpSocketWrapperReal {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UdpSocketWrapperTrait for UdpSocketWrapperReal {
    async fn bind(&mut self, addr: SocketAddr) -> io::Result<bool> {
        let socket = UdpSocket::bind(&addr).await?;
        self.delegate = Some(socket);
        Ok(true)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.delegate.as_ref() {
            Some(socket) => socket.recv_from(buf).await,
            None => panic!("call bind before recv_from"),
        }
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match self.delegate.as_ref() {
            Some(socket) => socket.send_to(buf, addr).await,
            None => panic!("call bind before send_to"),
        }
    }
}
