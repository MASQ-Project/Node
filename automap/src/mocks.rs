// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{
    FindRoutersCommand, FreePortFactory, UdpSocketWrapper, UdpSocketWrapperFactory,
};
use crate::comm_layer::{AutomapError, LocalIpFinder};
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use std::{io, thread};
use lazy_static::lazy_static;

lazy_static! {
    static ref MULTICAST_GROUPS_ACTIVE: Arc<Mutex<[u64; 4]>> = Arc::new (Mutex::new ([3, 0, 0, 0]));
}

pub struct TestMulticastSocketHolder {
    pub socket: UdpSocket,
    pub group: u8,
}

impl Drop for TestMulticastSocketHolder {
    fn drop(&mut self) {
        let ip = TestMulticastSocketHolder::ip_from_bit(self.group);
        self.socket.leave_multicast_v4(&ip, &Ipv4Addr::new (0, 0, 0, 0)).unwrap();
        let mut guard = MULTICAST_GROUPS_ACTIVE.lock().unwrap();
        TestMulticastSocketHolder::clear_bit(&mut guard, self.group);
    }
}

impl TestMulticastSocketHolder {
    pub fn checkout () -> TestMulticastSocketHolder {
        let group = Self::allocate_bit();
        let multicast = Self::ip_from_bit(group);
        let socket = UdpSocket::bind ("0.0.0.0:0").unwrap();
        socket.join_multicast_v4(&multicast, &Ipv4Addr::new (0, 0, 0, 0));
        Self { socket, group }
    }

    fn allocate_bit () -> u8 {
        let mut guard = MULTICAST_GROUPS_ACTIVE.lock().unwrap();
        let mut bit_idx = 0u8;
        while bit_idx <= 255 {
            if !Self::bit_at(&guard, bit_idx) {
                Self::set_bit (&mut guard, bit_idx);
                return bit_idx
            }
            bit_idx += 1;
        }
        panic! ("All test multicast groups are occupied");
    }

    fn bit_at (guard: &MutexGuard<[u64; 4]>, bit_idx: u8) -> bool {
        let (idx, mask) = Self::idx_and_mask_from_bit_idx(bit_idx);
        ((**guard)[idx] & mask) > 0
    }

    fn set_bit (guard: &mut MutexGuard<[u64; 4]>, bit_idx: u8) {
        let (idx, mask) = Self::idx_and_mask_from_bit_idx(bit_idx);
        (**guard)[idx] |= mask;
    }

    fn clear_bit (guard: &mut MutexGuard<[u64; 4]>, bit_idx: u8) {
        let (idx, mask) = Self::idx_and_mask_from_bit_idx(bit_idx);
        (**guard)[idx] &= !mask;
    }

    fn ip_from_bit (bit_idx: u8) -> Ipv4Addr {
        Ipv4Addr::new (224, 0, 0, bit_idx)
    }

    fn bit_idx_from_ip (ip: Ipv4Addr) -> u8 {
        ip.octets()[3]
    }

    fn idx_and_mask_from_bit_idx (bit_idx: u8) -> (usize, u64) {
        let idx = bit_idx >> 6;
        let pos = bit_idx & 0x3F;
        let mask = 1u64 << pos;
        (idx as usize, mask)
    }
}

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
    make_multicast_params: Arc<Mutex<Vec<(u8, u16, Ipv4Addr)>>>,
    make_multicast_results: RefCell<Vec<io::Result<Box<dyn UdpSocketWrapper>>>>,
}

impl UdpSocketWrapperFactory for UdpSocketWrapperFactoryMock {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        self.make_params.lock().unwrap().push(addr);
        self.make_results.borrow_mut().remove(0)
    }

    fn make_multicast(&self, multicast_group: u8, port: u16, interface: Ipv4Addr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        self.make_multicast_params.lock().unwrap().push((multicast_group, port, interface));
        self.make_multicast_results.borrow_mut().remove(0)
    }
}

impl UdpSocketWrapperFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
            make_multicast_params: Arc::new(Mutex::new(vec![])),
            make_multicast_results: RefCell::new(vec![]),
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

    pub fn make_multicast_params(mut self, params: &Arc<Mutex<Vec<(u8, u16, Ipv4Addr)>>>) -> Self {
        self.make_multicast_params = params.clone();
        self
    }

    pub fn make_multicast_result(self, result: io::Result<UdpSocketWrapperMock>) -> Self {
        self.make_multicast_results.borrow_mut().push(match result {
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
