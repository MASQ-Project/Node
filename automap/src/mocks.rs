// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{
    FindRoutersCommand, FreePortFactory, UdpSocketWrapper, UdpSocketWrapperFactory,
};
use crate::comm_layer::{AutomapError, LocalIpFinder};
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

pub struct LocalIpFinderMock {
    find_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
}

impl LocalIpFinder for LocalIpFinderMock {
    fn find(&self) -> Result<IpAddr, AutomapError> {
        self.find_results.borrow_mut().remove(0)
    }
}

impl LocalIpFinderMock {
    pub fn new() -> Self {
        Self {
            find_results: RefCell::new(vec![]),
        }
    }

    pub fn find_result(self, result: Result<IpAddr, AutomapError>) -> Self {
        self.find_results.borrow_mut().push(result);
        self
    }
}

pub struct UdpSocketWrapperMock {
    recv_from_params: Arc<Mutex<Vec<()>>>,
    recv_from_results: RefCell<Vec<(io::Result<(usize, SocketAddr)>, Vec<u8>)>>,
    send_to_params: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    send_to_results: RefCell<Vec<io::Result<usize>>>,
    set_read_timeout_params: Arc<Mutex<Vec<Option<Duration>>>>,
    set_read_timeout_results: RefCell<Vec<io::Result<()>>>,
}

impl UdpSocketWrapper for UdpSocketWrapperMock {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_params.lock().unwrap().push(());
        if self.recv_from_results.borrow().is_empty() {
            {
                let set_read_timeout_params_locked = self.set_read_timeout_params.lock().unwrap();
                if !set_read_timeout_params_locked.is_empty() {
                    let duration_opt = &set_read_timeout_params_locked[0];
                    match &duration_opt {
                        Some(duration) => thread::sleep(duration.clone()),
                        None => (),
                    }
                }
            }
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        let (result, bytes) = self.recv_from_results.borrow_mut().remove(0);
        for n in 0..bytes.len() {
            buf[n] = bytes[n];
        }
        result
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.send_to_params
            .lock()
            .unwrap()
            .push((buf.to_vec(), addr));
        self.send_to_results.borrow_mut().remove(0)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout_params.lock().unwrap().push(dur);
        self.set_read_timeout_results.borrow_mut().remove(0)
    }
}

impl UdpSocketWrapperMock {
    pub fn new() -> Self {
        Self {
            recv_from_params: Arc::new(Mutex::new(vec![])),
            recv_from_results: RefCell::new(vec![]),
            send_to_params: Arc::new(Mutex::new(vec![])),
            send_to_results: RefCell::new(vec![]),
            set_read_timeout_params: Arc::new(Mutex::new(vec![])),
            set_read_timeout_results: RefCell::new(vec![]),
        }
    }

    pub fn recv_from_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.recv_from_params = params.clone();
        self
    }

    pub fn recv_from_result(self, result: io::Result<(usize, SocketAddr)>, bytes: Vec<u8>) -> Self {
        self.recv_from_results.borrow_mut().push((result, bytes));
        self
    }

    pub fn send_to_params(mut self, params: &Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>) -> Self {
        self.send_to_params = params.clone();
        self
    }

    pub fn send_to_result(self, result: io::Result<usize>) -> Self {
        self.send_to_results.borrow_mut().push(result);
        self
    }

    pub fn set_read_timeout_params(mut self, params: &Arc<Mutex<Vec<Option<Duration>>>>) -> Self {
        self.set_read_timeout_params = params.clone();
        self
    }

    pub fn set_read_timeout_result(self, result: io::Result<()>) -> Self {
        self.set_read_timeout_results.borrow_mut().push(result);
        self
    }
}

pub struct UdpSocketWrapperFactoryMock {
    make_params: Arc<Mutex<Vec<SocketAddr>>>,
    make_results: RefCell<Vec<io::Result<Box<dyn UdpSocketWrapper>>>>,
}

impl UdpSocketWrapperFactory for UdpSocketWrapperFactoryMock {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        self.make_params.lock().unwrap().push(addr);
        self.make_results.borrow_mut().remove(0)
    }
}

impl UdpSocketWrapperFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<SocketAddr>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: io::Result<UdpSocketWrapperMock>) -> Self {
        self.make_results.borrow_mut().push(match result {
            Ok(uswm) => Ok(Box::new(uswm)),
            Err(e) => Err(e),
        });
        self
    }
}

pub struct FreePortFactoryMock {
    make_results: RefCell<Vec<u16>>,
}

impl FreePortFactory for FreePortFactoryMock {
    fn make(&self) -> u16 {
        self.make_results.borrow_mut().remove(0)
    }
}

impl FreePortFactoryMock {
    pub fn new() -> Self {
        Self {
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_result(self, result: u16) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

pub struct FindRoutersCommandMock {
    execute_result: Result<String, String>,
}

impl FindRoutersCommand for FindRoutersCommandMock {
    fn execute(&self) -> Result<String, String> {
        self.execute_result.clone()
    }
}

impl FindRoutersCommandMock {
    pub fn new(result: Result<&str, &str>) -> Self {
        Self {
            execute_result: match result {
                Ok(s) => Ok(s.to_string()),
                Err(s) => Err(s.to_string()),
            },
        }
    }
}
