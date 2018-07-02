// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::net::SocketAddr;
use std::marker::Send;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::prelude::Async;
use tokio::prelude::AsyncRead;
use tokio::prelude::AsyncWrite;

pub trait TokioListenerWrapper: Send {
    fn bind (&mut self, addr: SocketAddr) -> io::Result<()>;
    fn poll_accept (&mut self) -> Result<Async<(TcpStream, SocketAddr)>, io::Error>;
}

pub trait ReadHalfWrapper: Send {
    fn poll_read(&mut self, buf: &mut [u8]) -> Result<Async<usize>, io::Error>;
}

pub trait WriteHalfWrapper: Send {
    fn poll_write(&mut self, buf: &[u8]) -> Result<Async<usize>, io::Error>;
}

pub trait TokioListenerWrapperFactory {
    fn make (&self) -> Box<TokioListenerWrapper>;
}

pub struct TokioListenerWrapperReal {
    delegate: Option<TcpListener>,
}

pub struct ReadHalfWrapperReal {
    delegate: ReadHalf<TcpStream>
}

pub struct WriteHalfWrapperReal {
    delegate: WriteHalf<TcpStream>
}

pub struct TokioListenerWrapperFactoryReal {}

impl TokioListenerWrapper for TokioListenerWrapperReal {
    fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
        match TcpListener::bind (&addr) {
            Ok (tcp_listener) => {self.delegate = Some (tcp_listener); Ok (())},
            Err (e) => Err (e)
        }
   }

    fn poll_accept (&mut self) -> Result<Async<(TcpStream, SocketAddr)>, io::Error> {
        self.delegate_mut().poll_accept()
    }
}

impl ReadHalfWrapper for ReadHalfWrapperReal {
    fn poll_read(&mut self, buf: &mut [u8]) -> Result<Async<usize>, io::Error> {
        self.delegate.poll_read(buf)
    }
}

impl ReadHalfWrapperReal {
    pub fn new(reader: ReadHalf<TcpStream>) -> ReadHalfWrapperReal {
        ReadHalfWrapperReal { delegate: reader }
    }
}

impl WriteHalfWrapper for WriteHalfWrapperReal {
    fn poll_write(&mut self, buf: &[u8]) -> Result<Async<usize>, io::Error> {
        self.delegate.poll_write(buf)
    }
}

impl WriteHalfWrapperReal {
    pub fn new(writer: WriteHalf<TcpStream>) -> WriteHalfWrapperReal {
        WriteHalfWrapperReal { delegate: writer }
    }
}

impl TokioListenerWrapperFactory for TokioListenerWrapperFactoryReal {
    fn make(&self) -> Box<TokioListenerWrapper> {
        Box::new (TokioListenerWrapperReal {
            delegate: None
        })
    }
}

impl TokioListenerWrapperReal {
    pub fn new () -> TokioListenerWrapperReal {
        TokioListenerWrapperReal {delegate: None}
    }

    fn delegate_mut (&mut self) -> &mut TcpListener {
        self.delegate.as_mut().expect ("TcpListener not initialized - bind to a SocketAddr")
    }
}

#[cfg (test)]
mod tests {

    #[test]
    fn nothing () {

    }
}