// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::io;
use std::io::Read;
use std::io::Write;
use std::marker::Send;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

pub trait TcpStreamWrapper: Send + Read + Write {
    fn connect(&mut self, addr: SocketAddr) -> io::Result<()>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn read_timeout(&self) -> io::Result<Option<Duration>>;
    fn write_timeout(&self) -> io::Result<Option<Duration>>;
    fn peek(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
    fn nodelay(&self) -> io::Result<bool>;
    fn set_ttl(&self, ttl: u32) -> io::Result<()>;
    fn ttl(&self) -> io::Result<u32>;
    fn take_error(&self) -> io::Result<Option<io::Error>>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn try_clone(&self) -> io::Result<Box<dyn TcpStreamWrapper>>;
}

pub trait TcpStreamWrapperFactory: Send {
    fn make(&self) -> Box<dyn TcpStreamWrapper>;
    fn dup(&self) -> Box<dyn TcpStreamWrapperFactory>;
}

#[derive(Default)]
pub struct TcpStreamWrapperReal {
    delegate: Option<TcpStream>,
}

#[derive(Clone)]
pub struct TcpStreamWrapperFactoryReal {}

impl TcpStreamWrapper for TcpStreamWrapperReal {
    fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        match TcpStream::connect(addr) {
            Ok(tcp_stream) => {
                self.delegate = Some(tcp_stream);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.delegate().peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.delegate().local_addr()
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.delegate().shutdown(how)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.delegate().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.delegate().set_write_timeout(dur)
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.delegate().read_timeout()
    }

    fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.delegate().write_timeout()
    }

    fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.delegate().peek(buf)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.delegate().set_nodelay(nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        self.delegate().nodelay()
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.delegate().set_ttl(ttl)
    }

    fn ttl(&self) -> io::Result<u32> {
        self.delegate().ttl()
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.delegate().take_error()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.delegate().set_nonblocking(nonblocking)
    }

    fn try_clone(&self) -> io::Result<Box<dyn TcpStreamWrapper>> {
        match self.delegate().try_clone() {
            Ok(c) => Ok(Box::new(TcpStreamWrapperReal { delegate: Some(c) })),
            Err(e) => Err(e),
        }
    }
}

impl Read for TcpStreamWrapperReal {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.delegate_mut().read(buf)
    }
}

impl Write for TcpStreamWrapperReal {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.delegate_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.delegate_mut().flush()
    }
}

impl TcpStreamWrapperFactory for TcpStreamWrapperFactoryReal {
    fn make(&self) -> Box<dyn TcpStreamWrapper> {
        Box::new(TcpStreamWrapperReal { delegate: None })
    }
    fn dup(&self) -> Box<dyn TcpStreamWrapperFactory> {
        Box::new(self.clone())
    }
}

impl TcpStreamWrapperReal {
    pub fn new() -> Self {
        Self::default()
    }

    fn delegate(&self) -> &TcpStream {
        self.delegate
            .as_ref()
            .expect("TcpStream not initialized - connect to a SocketAddr")
    }

    fn delegate_mut(&mut self) -> &mut TcpStream {
        self.delegate
            .as_mut()
            .expect("TcpStream not initialized - connect to a SocketAddr")
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn nothing() {}
}
