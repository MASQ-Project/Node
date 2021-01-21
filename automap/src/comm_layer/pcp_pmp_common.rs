// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub use std::net::UdpSocket;
use std::net::{SocketAddr, ToSocketAddrs};
use std::io;
use std::time::Duration;

pub trait UdpSocketWrapper {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
}

pub struct UdpSocketReal {
    delegate: UdpSocket,
}

impl UdpSocketWrapper for UdpSocketReal {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.delegate.recv_from (buf)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.delegate.send_to (buf, addr)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.delegate.set_read_timeout (dur)
    }
}

impl UdpSocketReal {
    pub fn new (delegate: UdpSocket) -> Self {
        Self {
            delegate
        }
    }
}

pub trait UdpSocketFactory {
    fn make (&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>>;
}

pub struct UdpSocketFactoryReal {}

impl UdpSocketFactory for UdpSocketFactoryReal {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        Ok(Box::new (UdpSocketReal::new (UdpSocket::bind(addr)?)))
    }
}

impl UdpSocketFactoryReal {
    pub fn new () -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;
    use std::sync::{Mutex, Arc};
    use std::cell::RefCell;

    pub struct UdpSocketMock {
        recv_from_params: Arc<Mutex<Vec<()>>>,
        recv_from_results: RefCell<Vec<(io::Result<(usize, SocketAddr)>, Vec<u8>)>>,
        send_to_params: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
        send_to_results: RefCell<Vec<io::Result<usize>>>,
        set_read_timeout_params: Arc<Mutex<Vec<Option<Duration>>>>,
        set_read_timeout_results: RefCell<Vec<io::Result<()>>>,
    }

    impl UdpSocketWrapper for UdpSocketMock {
        fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.recv_from_params.lock().unwrap().push (());
            let (result, bytes) = self.recv_from_results.borrow_mut().remove(0);
            for n in 0..bytes.len() {buf[n] = bytes[n];}
            result
        }

        fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.send_to_params.lock().unwrap().push ((buf.to_vec(), addr));
            self.send_to_results.borrow_mut().remove (0)
        }

        fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            self.set_read_timeout_params.lock().unwrap().push (dur);
            self.set_read_timeout_results.borrow_mut().remove(0)
        }
    }

    impl UdpSocketMock {
        pub fn new () -> Self {
            Self {
                recv_from_params: Arc::new(Mutex::new(vec![])),
                recv_from_results: RefCell::new(vec![]),
                send_to_params: Arc::new(Mutex::new(vec![])),
                send_to_results: RefCell::new(vec![]),
                set_read_timeout_params: Arc::new(Mutex::new(vec![])),
                set_read_timeout_results: RefCell::new(vec![])
            }
        }

        pub fn recv_from_params (mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.recv_from_params = params.clone();
            self
        }

        pub fn recv_from_result (self, result: io::Result<(usize, SocketAddr)>, bytes: Vec<u8>) -> Self {
            self.recv_from_results.borrow_mut().push ((result, bytes));
            self
        }

        pub fn send_to_params (mut self, params: &Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>) -> Self {
            self.send_to_params = params.clone();
            self
        }

        pub fn send_to_result (self, result: io::Result<usize>) -> Self {
            self.send_to_results.borrow_mut().push (result);
            self
        }

        pub fn set_read_timeout_params (mut self, params: &Arc<Mutex<Vec<Option<Duration>>>>) -> Self {
            self.set_read_timeout_params = params.clone();
            self
        }

        pub fn set_read_timeout_result (self, result: io::Result<()>) -> Self {
            self.set_read_timeout_results.borrow_mut().push (result);
            self
        }
    }

    pub struct UdpSocketFactoryMock {
        make_params: Arc<Mutex<Vec<SocketAddr>>>,
        make_results: RefCell<Vec<io::Result<UdpSocketMock>>>,
    }

    impl UdpSocketFactory for UdpSocketFactoryMock {
        fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
            self.make_params.lock().unwrap().push (addr);
            Ok (Box::new (self.make_results.borrow_mut().remove(0)?))
        }
    }

    impl UdpSocketFactoryMock {
        pub fn new () -> Self {
            Self {
                make_params: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![])
            }
        }

        pub fn make_params (mut self, params: &Arc<Mutex<Vec<SocketAddr>>>) -> Self {
            self.make_params = params.clone();
            self
        }

        pub fn make_result (self, result: io::Result<UdpSocketMock>) -> Self {
            self.make_results.borrow_mut().push (result);
            self
        }
    }
}
