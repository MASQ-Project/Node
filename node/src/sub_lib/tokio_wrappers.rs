// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::io;
use std::marker::Send;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

pub trait TokioListenerWrapper: Send {
    fn bind(&mut self, addr: SocketAddr) -> io::Result<()>;
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>>;
}

pub trait ReadHalfWrapper: Send + AsyncRead {}

pub trait WriteHalfWrapper: Send + AsyncWrite {}

pub trait TokioListenerWrapperFactory {
    fn make(&self) -> Box<dyn TokioListenerWrapper>;
}

#[derive(Default)]
pub struct TokioListenerWrapperReal {
    delegate: Option<TcpListener>,
}

pub struct ReadHalfWrapperReal {
    delegate: OwnedReadHalf,
}

pub struct WriteHalfWrapperReal {
    delegate: OwnedWriteHalf,
}

pub struct TokioListenerWrapperFactoryReal {}

impl TokioListenerWrapper for TokioListenerWrapperReal {
    fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
        match TcpListener::bind(&addr) {
            Ok(tcp_listener) => {
                self.delegate = Some(tcp_listener);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        self.delegate().poll_accept(cx)
    }
}

impl AsyncRead for ReadHalfWrapperReal {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.delegate.poll_read(cx, buf)
    }
}

impl ReadHalfWrapper for ReadHalfWrapperReal {}

impl ReadHalfWrapperReal {
    pub fn new(reader: OwnedReadHalf) -> ReadHalfWrapperReal {
        ReadHalfWrapperReal { delegate: reader }
    }
}

impl AsyncWrite for WriteHalfWrapperReal {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.delegate.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.delegate.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.delegate.poll_shutdown(cx)
    }
}

impl WriteHalfWrapper for WriteHalfWrapperReal {}

impl WriteHalfWrapperReal {
    pub fn new(writer: OwnedWriteHalf) -> WriteHalfWrapperReal {
        WriteHalfWrapperReal { delegate: writer }
    }
}

impl TokioListenerWrapperFactory for TokioListenerWrapperFactoryReal {
    fn make(&self) -> Box<dyn TokioListenerWrapper> {
        Box::new(TokioListenerWrapperReal { delegate: None })
    }
}

impl TokioListenerWrapperReal {
    pub fn new() -> Self {
        Self::default()
    }

    fn delegate(&self) -> &TcpListener {
        &self
            .delegate
            .expect("TcpListener not initialized - bind to a SocketAddr")
    }

    fn delegate_mut(&mut self) -> &mut TcpListener {
        self.delegate
            .as_mut()
            .expect("TcpListener not initialized - bind to a SocketAddr")
    }
}
