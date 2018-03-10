// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::io::Result;
use std::net::UdpSocket;
use std::net::SocketAddr;
use std::marker::Sized;
use std::marker::Send;
use std::time::Duration;

pub trait UdpSocketWrapperTrait: Sized + Send {
    fn bind (&mut self, addr: SocketAddr) -> io::Result<bool>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()>;
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to (&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
}

pub struct UdpSocketWrapperReal {
    socket_opt: Option<UdpSocket>
}

impl UdpSocketWrapperReal {
    pub fn new () -> UdpSocketWrapperReal {
        UdpSocketWrapperReal {socket_opt: None}
    }
}

impl UdpSocketWrapperTrait for UdpSocketWrapperReal {
    fn bind (&mut self, addr: SocketAddr) -> io::Result<bool> {
        let socket = UdpSocket::bind (addr)?;
        self.socket_opt = Some (socket);
        Ok (true)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        match self.socket_opt {
            Some (ref socket) => socket.set_read_timeout (dur),
            None => panic! ("call bind before set_read_timeout")
        }
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.socket_opt {
            Some (ref socket) => socket.recv_from (buf),
            None => panic! ("call bind before recv_from")
        }
    }

    fn send_to (&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match self.socket_opt {
            Some (ref socket) => socket.send_to (buf, addr),
            None => panic! ("call bind before send_to")
        }
    }
}
