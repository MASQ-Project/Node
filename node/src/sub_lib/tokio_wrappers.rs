// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::io;
use std::marker::Send;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

#[async_trait]
pub trait TokioListenerWrapper: Send {
    async fn bind(&mut self, addr: SocketAddr) -> io::Result<()>;
    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)>;

    // TODO: See if we can get rid of this
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>>;
}

#[async_trait]
pub trait ReadHalfWrapper: Send {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait WriteHalfWrapper: Send {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    async fn flush(&mut self) -> io::Result<()>;
    async fn shutdown(&mut self) -> io::Result<()>;
}

pub trait TokioListenerWrapperFactory {
    fn make(&self) -> Box<dyn TokioListenerWrapper>;
}

// TODO: Another embarrassing optional delegate. The optionality should be taken care of by
// TokioListenerWrapperFactory.
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

#[async_trait]
impl TokioListenerWrapper for TokioListenerWrapperReal {
    async fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
        match TcpListener::bind(&addr).await {
            Ok(tcp_listener) => {
                self.delegate = Some(tcp_listener);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.delegate().accept().await
    }

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        todo!("See if we can get rid of this");
        self.delegate().poll_accept(cx)
    }
}

#[async_trait]
impl ReadHalfWrapper for ReadHalfWrapperReal {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.delegate.read(buf).await
    }
}

impl ReadHalfWrapperReal {
    pub fn new(reader: OwnedReadHalf) -> ReadHalfWrapperReal {
        ReadHalfWrapperReal { delegate: reader }
    }
}

#[async_trait]
impl WriteHalfWrapper for WriteHalfWrapperReal {
    async fn write(
        self: &mut Self,
        buf: &[u8],
    ) -> io::Result<usize> {
        self.delegate.write(&buf).await
    }

    async fn flush(self: &mut Self) -> io::Result<()> {
        self.delegate.flush().await
    }

    async fn shutdown(self: &mut Self) -> io::Result<()> {
        self.delegate.shutdown().await
    }
}

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
        self
            .delegate
            .as_ref()
            .expect("TcpListener not initialized - bind to a SocketAddr")
    }

    fn delegate_mut(&mut self) -> &mut TcpListener {
        self.delegate
            .as_mut()
            .expect("TcpListener not initialized - bind to a SocketAddr")
    }
}
