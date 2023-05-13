// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{CommandError, CommandOutput, FindRoutersCommand, FreePortFactory, UdpSocketWrapper, UdpSocketWrapperFactory, UdpSocketWrapperFactoryReal};
use crate::comm_layer::{AutomapError, HousekeepingThreadCommand, LocalIpFinder, LocalIpFinderReal, Transactor};
use crate::control_layer::automap_control::{AutomapControlReal, ChangeHandler, replace_transactor};
use crossbeam_channel::Sender;
use lazy_static::lazy_static;
use masq_lib::utils::{AutomapProtocol, find_free_port};
use std::any::Any;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use std::{io, thread};

lazy_static! {
    pub static ref ROUTER_IP: IpAddr = IpAddr::from_str("1.2.3.4").unwrap();
    pub static ref PUBLIC_IP: IpAddr = IpAddr::from_str("2.3.4.5").unwrap();
    static ref MULTICAST_GROUPS_ACTIVE: Arc<Mutex<[u64; 4]>> = Arc::new(Mutex::new([3, 0, 0, 0]));
}

pub struct TestMulticastSocketHolder {
    pub socket: Box<dyn UdpSocketWrapper>,
    pub group: u8,
}

impl Drop for TestMulticastSocketHolder {
    fn drop(&mut self) {
        let ip = TestMulticastSocketHolder::ip_from_bit(self.group);
        self.socket
            .as_ref()
            .leave_multicast_v4(&ip, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let mut guard = MULTICAST_GROUPS_ACTIVE.lock().unwrap();
        TestMulticastSocketHolder::clear_bit(&mut guard, self.group);
    }
}

impl TestMulticastSocketHolder {
    pub fn checkout(port: u16) -> TestMulticastSocketHolder {
        let factory = UdpSocketWrapperFactoryReal::new();
        let multicast_group = Self::allocate_bit();
        let socket = factory.make_multicast(multicast_group, port).unwrap();
        Self {
            socket,
            group: multicast_group,
        }
    }

    fn allocate_bit() -> u8 {
        let mut guard = MULTICAST_GROUPS_ACTIVE.lock().unwrap();
        let mut bit_idx = 0u8;
        while bit_idx <= 250 {
            // 251-254 are reserved for special-purpose tests
            if !Self::bit_at(&guard, bit_idx) {
                Self::set_bit(&mut guard, bit_idx);
                return bit_idx;
            }
            bit_idx += 1;
        }
        panic!("All test multicast groups are occupied");
    }

    fn bit_at(guard: &MutexGuard<[u64; 4]>, bit_idx: u8) -> bool {
        let (idx, mask) = Self::idx_and_mask_from_bit_idx(bit_idx);
        ((**guard)[idx] & mask) > 0
    }

    fn set_bit(guard: &mut MutexGuard<[u64; 4]>, bit_idx: u8) {
        let (idx, mask) = Self::idx_and_mask_from_bit_idx(bit_idx);
        (**guard)[idx] |= mask;
    }

    fn clear_bit(guard: &mut MutexGuard<[u64; 4]>, bit_idx: u8) {
        let (idx, mask) = Self::idx_and_mask_from_bit_idx(bit_idx);
        (**guard)[idx] &= !mask;
    }

    fn ip_from_bit(bit_idx: u8) -> Ipv4Addr {
        Ipv4Addr::new(224, 0, 0, bit_idx)
    }

    fn _bit_idx_from_ip(ip: Ipv4Addr) -> u8 {
        ip.octets()[3]
    }

    fn idx_and_mask_from_bit_idx(bit_idx: u8) -> (usize, u64) {
        let idx = bit_idx >> 6;
        let pos = bit_idx & 0x3F;
        let mask = 1u64 << pos;
        (idx as usize, mask)
    }
}

pub struct RouterConnections {
    pub holder: TestMulticastSocketHolder,
    pub announcement_port: u16,
    pub router_ip: IpAddr,
    pub router_port: u16,
    pub multicast_address: SocketAddr,
}

pub fn make_router_connections() -> RouterConnections {
    let announcement_port = find_free_port();
    let holder = TestMulticastSocketHolder::checkout(announcement_port);
    let router_port = find_free_port();
    let router_ip = LocalIpFinderReal::new().find().unwrap();
    let multicast_address = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, holder.group)),
        announcement_port,
    );
    RouterConnections {
        holder,
        announcement_port,
        router_ip,
        router_port,
        multicast_address,
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
    #[allow(clippy::new_without_default)]
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

#[allow(clippy::type_complexity)]
pub struct UdpSocketWrapperMock {
    local_addr_results: RefCell<Vec<io::Result<SocketAddr>>>,
    peer_addr_results: RefCell<Vec<io::Result<SocketAddr>>>,
    connect_params: Arc<Mutex<Vec<SocketAddr>>>,
    connect_results: RefCell<Vec<io::Result<()>>>,
    recv_from_params: Arc<Mutex<Vec<()>>>,
    recv_from_results: RefCell<Vec<(io::Result<(usize, SocketAddr)>, Vec<u8>)>>,
    send_to_params: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    send_to_results: RefCell<Vec<io::Result<usize>>>,
    send_params: Arc<Mutex<Vec<Vec<u8>>>>,
    send_results: RefCell<Vec<io::Result<usize>>>,
    set_read_timeout_params: Arc<Mutex<Vec<Option<Duration>>>>,
    set_read_timeout_results: RefCell<Vec<io::Result<()>>>,
    leave_multicast_v4_params: Arc<Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>>,
    leave_multicast_v4_results: RefCell<Vec<io::Result<()>>>,
}

impl UdpSocketWrapper for UdpSocketWrapperMock {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr_results.borrow_mut().remove(0)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr_results.borrow_mut().remove(0)
    }

    fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.connect_params.lock().unwrap().push(addr);
        self.connect_results.borrow_mut().remove(0)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_params.lock().unwrap().push(());
        if self.recv_from_results.borrow().is_empty() {
            {
                let set_read_timeout_params_locked = self.set_read_timeout_params.lock().unwrap();
                if !set_read_timeout_params_locked.is_empty() {
                    let duration_opt = &set_read_timeout_params_locked[0];
                    match &duration_opt {
                        Some(duration) => thread::sleep(*duration),
                        None => (),
                    }
                }
            }
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        let (result, bytes) = self.recv_from_results.borrow_mut().remove(0);
        buf[..bytes.len()].clone_from_slice(&bytes[..]);
        result
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.send_to_params
            .lock()
            .unwrap()
            .push((buf.to_vec(), addr));
        self.send_to_results.borrow_mut().remove(0)
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_params.lock().unwrap().push(buf.to_vec());
        self.send_results.borrow_mut().remove(0)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout_params.lock().unwrap().push(dur);
        self.set_read_timeout_results.borrow_mut().remove(0)
    }

    fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.leave_multicast_v4_params
            .lock()
            .unwrap()
            .push((*multiaddr, *interface));
        self.leave_multicast_v4_results.borrow_mut().remove(0)
    }
}

impl UdpSocketWrapperMock {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            local_addr_results: RefCell::new(vec![]),
            peer_addr_results: RefCell::new(vec![]),
            connect_params: Arc::new(Mutex::new(vec![])),
            connect_results: RefCell::new(vec![]),
            recv_from_params: Arc::new(Mutex::new(vec![])),
            recv_from_results: RefCell::new(vec![]),
            send_to_params: Arc::new(Mutex::new(vec![])),
            send_to_results: RefCell::new(vec![]),
            send_params: Arc::new(Mutex::new(vec![])),
            send_results: RefCell::new(vec![]),
            set_read_timeout_params: Arc::new(Mutex::new(vec![])),
            set_read_timeout_results: RefCell::new(vec![]),
            leave_multicast_v4_params: Arc::new(Mutex::new(vec![])),
            leave_multicast_v4_results: RefCell::new(vec![]),
        }
    }

    pub fn local_addr_result(self, result: io::Result<SocketAddr>) -> Self {
        self.local_addr_results.borrow_mut().push(result);
        self
    }

    pub fn peer_addr_result(self, result: io::Result<SocketAddr>) -> Self {
        self.peer_addr_results.borrow_mut().push(result);
        self
    }

    pub fn connect_params(mut self, params: &Arc<Mutex<Vec<SocketAddr>>>) -> Self {
        self.connect_params = params.clone();
        self
    }

    pub fn connect_result(self, result: io::Result<()>) -> Self {
        self.connect_results.borrow_mut().push(result);
        self
    }

    pub fn recv_from_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.recv_from_params = params.clone();
        self
    }

    pub fn recv_from_result(self, result: io::Result<(usize, SocketAddr)>, bytes: Vec<u8>) -> Self {
        self.recv_from_results.borrow_mut().push((result, bytes));
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn send_to_params(mut self, params: &Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>) -> Self {
        self.send_to_params = params.clone();
        self
    }

    pub fn send_to_result(self, result: io::Result<usize>) -> Self {
        self.send_to_results.borrow_mut().push(result);
        self
    }

    pub fn send_params(mut self, params: &Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        self.send_params = params.clone();
        self
    }

    pub fn send_result(self, result: io::Result<usize>) -> Self {
        self.send_results.borrow_mut().push(result);
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

    pub fn leave_multicast_v4_params(
        mut self,
        params: &Arc<Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>>,
    ) -> Self {
        self.leave_multicast_v4_params = params.clone();
        self
    }

    pub fn leave_multicast_v4_result(self, result: io::Result<()>) -> Self {
        self.leave_multicast_v4_results.borrow_mut().push(result);
        self
    }
}

pub struct UdpSocketWrapperFactoryMock {
    make_params: Arc<Mutex<Vec<SocketAddr>>>,
    make_results: RefCell<Vec<io::Result<Box<dyn UdpSocketWrapper>>>>,
    make_multicast_params: Arc<Mutex<Vec<(u8, u16)>>>,
    make_multicast_results: RefCell<Vec<io::Result<Box<dyn UdpSocketWrapper>>>>,
}

impl UdpSocketWrapperFactory for UdpSocketWrapperFactoryMock {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        self.make_params.lock().unwrap().push(addr);
        self.make_results.borrow_mut().remove(0)
    }

    fn make_multicast(
        &self,
        multicast_group: u8,
        port: u16,
    ) -> io::Result<Box<dyn UdpSocketWrapper>> {
        self.make_multicast_params
            .lock()
            .unwrap()
            .push((multicast_group, port));
        self.make_multicast_results.borrow_mut().remove(0)
    }
}

impl Default for UdpSocketWrapperFactoryMock {
    fn default() -> Self {
        Self::new()
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

    #[allow(clippy::type_complexity)]
    pub fn make_multicast_params(mut self, params: &Arc<Mutex<Vec<(u8, u16)>>>) -> Self {
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
    #[allow(clippy::new_without_default)]
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
    execute_results: RefCell<Vec<Result<CommandOutput, CommandError>>>,
}

impl FindRoutersCommand for FindRoutersCommandMock {
    fn execute(&self) -> Result<CommandOutput, CommandError> {
        self.execute_results.borrow_mut().remove(0)
    }
}

impl Default for FindRoutersCommandMock {
    fn default() -> Self {
        Self::new()
    }
}

impl FindRoutersCommandMock {
    pub fn new() -> Self {
        Self {
            execute_results: RefCell::new(vec![]),
        }
    }

    pub fn execute_result(self, result: Result<CommandOutput, CommandError>) -> Self {
        self.execute_results.borrow_mut().push(result);
        self
    }
}

pub struct TransactorMock {
    pub housekeeping_thread_started: bool,
    protocol: AutomapProtocol,
    find_routers_results: RefCell<Vec<Result<Vec<IpAddr>, AutomapError>>>,
    get_public_ip_params: Arc<Mutex<Vec<IpAddr>>>,
    get_public_ip_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
    add_mapping_params: Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
    add_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
    add_permanent_mapping_params: Arc<Mutex<Vec<(IpAddr, u16)>>>,
    add_permanent_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
    delete_mapping_params: Arc<Mutex<Vec<(IpAddr, u16)>>>,
    delete_mapping_results: RefCell<Vec<Result<(), AutomapError>>>,
    start_housekeeping_thread_params: Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
    start_housekeeping_thread_results:
        RefCell<Vec<Result<Sender<HousekeepingThreadCommand>, AutomapError>>>,
    stop_housekeeping_thread_params: Arc<Mutex<Vec<()>>>,
    stop_housekeeping_thread_results: RefCell<Vec<Result<ChangeHandler, AutomapError>>>,
}

impl Transactor for TransactorMock {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        self.find_routers_results.borrow_mut().remove(0)
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        if !self.housekeeping_thread_started {
            panic!("Housekeeping thread must be started before get_public_ip()")
        }
        self.get_public_ip_params.lock().unwrap().push(router_ip);
        self.get_public_ip_results.borrow_mut().remove(0)
    }

    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        if !self.housekeeping_thread_started {
            panic!("Housekeeping thread must be started before add_mapping()")
        }
        self.add_mapping_params
            .lock()
            .unwrap()
            .push((router_ip, hole_port, lifetime));
        self.add_mapping_results.borrow_mut().remove(0)
    }

    fn add_permanent_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
    ) -> Result<u32, AutomapError> {
        if !self.housekeeping_thread_started {
            panic!("Housekeeping thread must be started before add_permanent_mapping()")
        }
        self.add_permanent_mapping_params
            .lock()
            .unwrap()
            .push((router_ip, hole_port));
        self.add_permanent_mapping_results.borrow_mut().remove(0)
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        self.delete_mapping_params
            .lock()
            .unwrap()
            .push((router_ip, hole_port));
        self.delete_mapping_results.borrow_mut().remove(0)
    }

    fn protocol(&self) -> AutomapProtocol {
        self.protocol
    }

    fn start_housekeeping_thread(
        &mut self,
        change_handler: ChangeHandler,
        router_ip: IpAddr,
    ) -> Result<Sender<HousekeepingThreadCommand>, AutomapError> {
        self.start_housekeeping_thread_params
            .lock()
            .unwrap()
            .push((change_handler, router_ip));
        let result = self
            .start_housekeeping_thread_results
            .borrow_mut()
            .remove(0);
        self.housekeeping_thread_started = true;
        result
    }

    fn stop_housekeeping_thread(&mut self) -> Result<ChangeHandler, AutomapError> {
        self.stop_housekeeping_thread_params
            .lock()
            .unwrap()
            .push(());
        let result = self.stop_housekeeping_thread_results.borrow_mut().remove(0);
        self.housekeeping_thread_started = false;
        result
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TransactorMock {
    pub fn new(protocol: AutomapProtocol) -> Self {
        Self {
            housekeeping_thread_started: false,
            protocol,
            find_routers_results: RefCell::new(vec![]),
            get_public_ip_params: Arc::new(Mutex::new(vec![])),
            get_public_ip_results: RefCell::new(vec![]),
            add_mapping_params: Arc::new(Mutex::new(vec![])),
            add_mapping_results: RefCell::new(vec![]),
            add_permanent_mapping_params: Arc::new(Mutex::new(vec![])),
            add_permanent_mapping_results: RefCell::new(vec![]),
            delete_mapping_params: Arc::new(Mutex::new(vec![])),
            delete_mapping_results: RefCell::new(vec![]),
            start_housekeeping_thread_params: Arc::new(Mutex::new(vec![])),
            start_housekeeping_thread_results: RefCell::new(vec![]),
            stop_housekeeping_thread_params: Arc::new(Mutex::new(vec![])),
            stop_housekeeping_thread_results: RefCell::new(vec![]),
        }
    }

    pub fn find_routers_result(self, result: Result<Vec<IpAddr>, AutomapError>) -> Self {
        self.find_routers_results.borrow_mut().push(result);
        self
    }

    pub fn get_public_ip_params(mut self, params: &Arc<Mutex<Vec<IpAddr>>>) -> Self {
        self.get_public_ip_params = params.clone();
        self
    }

    pub fn get_public_ip_result(self, result: Result<IpAddr, AutomapError>) -> Self {
        self.get_public_ip_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn add_mapping_params(mut self, params: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>) -> Self {
        self.add_mapping_params = params.clone();
        self
    }

    pub fn add_mapping_result(self, result: Result<u32, AutomapError>) -> Self {
        self.add_mapping_results.borrow_mut().push(result);
        self
    }

    pub fn add_permanent_mapping_params(mut self, params: &Arc<Mutex<Vec<(IpAddr, u16)>>>) -> Self {
        self.add_permanent_mapping_params = params.clone();
        self
    }

    pub fn add_permanent_mapping_result(self, result: Result<u32, AutomapError>) -> Self {
        self.add_permanent_mapping_results.borrow_mut().push(result);
        self
    }

    pub fn delete_mapping_params(mut self, params: &Arc<Mutex<Vec<(IpAddr, u16)>>>) -> Self {
        self.delete_mapping_params = params.clone();
        self
    }

    pub fn delete_mapping_result(self, result: Result<(), AutomapError>) -> Self {
        self.delete_mapping_results.borrow_mut().push(result);
        self
    }

    pub fn start_housekeeping_thread_result(
        self,
        result: Result<Sender<HousekeepingThreadCommand>, AutomapError>,
    ) -> Self {
        self.start_housekeeping_thread_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn start_housekeeping_thread_params(
        mut self,
        params: &Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
    ) -> Self {
        self.start_housekeeping_thread_params = params.clone();
        self
    }

    pub fn stop_housekeeping_thread_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.stop_housekeeping_thread_params = params.clone();
        self
    }

    pub fn stop_housekeeping_thread_result(
        self,
        result: Result<ChangeHandler, AutomapError>,
    ) -> Self {
        self.stop_housekeeping_thread_results
            .borrow_mut()
            .push(result);
        self
    }
}

pub fn parameterizable_automap_control(
    change_handler: ChangeHandler,
    usual_protocol_opt: Option<AutomapProtocol>,
    mock_transactors: Vec<TransactorMock>,
) -> AutomapControlReal {
    let subject = AutomapControlReal::new(usual_protocol_opt, change_handler);
    mock_transactors
        .into_iter()
        .fold(subject, |mut subject_so_far, transactor| {
            subject_so_far = replace_transactor(subject_so_far, Box::new(transactor));
            subject_so_far
        })
}
