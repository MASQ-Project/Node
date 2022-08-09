// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(any(test, not(feature = "no_test_share")))]

use crate::comm_layer::pcp_pmp_common::{
    FindRoutersCommand, FreePortFactory, PoliteUdpSocketWrapperFactory, UdpSocketWrapper,
    UdpSocketWrapperFactory,
};
use crate::comm_layer::{
    AutomapError, HousekeepingThreadCommand, LocalIpFinder, MulticastInfo, Transactor,
};
use crate::control_layer::automap_control::{
    replace_transactor, AutomapChange, AutomapControlReal, ChangeHandler,
};
use crossbeam_channel::Sender;
use lazy_static::lazy_static;
use masq_lib::utils::AutomapProtocol;
use std::any::Any;
use std::cell::RefCell;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{io, thread};

lazy_static! {
    pub static ref ROUTER_IP: IpAddr = IpAddr::from_str("1.2.3.4").unwrap();
    pub static ref PUBLIC_IP: IpAddr = IpAddr::from_str("2.3.4.5").unwrap();
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
    recv_params: Arc<Mutex<Vec<()>>>,
    recv_results: RefCell<Vec<(io::Result<usize>, Vec<u8>)>>,
    recv_from_params: Arc<Mutex<Vec<()>>>,
    recv_from_results: RefCell<Vec<(io::Result<(usize, SocketAddr)>, Vec<u8>)>>,
    send_to_params: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    send_to_results: RefCell<Vec<io::Result<usize>>>,
    set_read_timeout_params: Arc<Mutex<Vec<Option<Duration>>>>,
    set_read_timeout_results: RefCell<Vec<io::Result<()>>>,
    set_nonblocking_params: Arc<Mutex<Vec<bool>>>,
    set_nonblocking_results: RefCell<Vec<io::Result<()>>>,
}

impl UdpSocketWrapper for UdpSocketWrapperMock {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_params.lock().unwrap().push(());
        if self.recv_results.borrow().is_empty() {
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
        let (result, bytes) = self.recv_results.borrow_mut().remove(0);
        buf[..bytes.len()].clone_from_slice(&bytes[..]);
        result
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

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout_params.lock().unwrap().push(dur);
        self.set_read_timeout_results.borrow_mut().remove(0)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking_params
            .lock()
            .unwrap()
            .push(nonblocking);
        self.set_nonblocking_results.borrow_mut().remove(0)
    }
}

impl UdpSocketWrapperMock {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            recv_params: Arc::new(Mutex::new(vec![])),
            recv_results: RefCell::new(vec![]),
            recv_from_params: Arc::new(Mutex::new(vec![])),
            recv_from_results: RefCell::new(vec![]),
            send_to_params: Arc::new(Mutex::new(vec![])),
            send_to_results: RefCell::new(vec![]),
            set_read_timeout_params: Arc::new(Mutex::new(vec![])),
            set_read_timeout_results: RefCell::new(vec![]),
            set_nonblocking_params: Arc::new(Mutex::new(vec![])),
            set_nonblocking_results: RefCell::new(vec![]),
        }
    }

    pub fn recv_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.recv_params = params.clone();
        self
    }

    pub fn recv_result(self, result: io::Result<usize>, bytes: Vec<u8>) -> Self {
        self.recv_results.borrow_mut().push((result, bytes));
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

    pub fn set_read_timeout_params(mut self, params: &Arc<Mutex<Vec<Option<Duration>>>>) -> Self {
        self.set_read_timeout_params = params.clone();
        self
    }

    pub fn set_read_timeout_result(self, result: io::Result<()>) -> Self {
        self.set_read_timeout_results.borrow_mut().push(result);
        self
    }

    pub fn set_nonblocking_params(mut self, params: &Arc<Mutex<Vec<bool>>>) -> Self {
        self.set_nonblocking_params = params.clone();
        self
    }

    pub fn set_nonblocking_result(self, result: io::Result<()>) -> Self {
        self.set_nonblocking_results.borrow_mut().push(result);
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
    #[allow(clippy::new_without_default)]
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

pub struct PoliteUdpSocketWrapperFactoryMock {
    make_params: Arc<Mutex<Vec<MulticastInfo>>>,
    make_results: RefCell<Vec<io::Result<Box<dyn UdpSocketWrapper>>>>,
}

impl PoliteUdpSocketWrapperFactory for PoliteUdpSocketWrapperFactoryMock {
    fn make(&self, multicast_info: &MulticastInfo) -> io::Result<Box<dyn UdpSocketWrapper>> {
        self.make_params
            .lock()
            .unwrap()
            .push(multicast_info.clone());
        self.make_results.borrow_mut().remove(0)
    }
}

impl PoliteUdpSocketWrapperFactoryMock {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<MulticastInfo>>>) -> Self {
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

pub struct TransactorMock {
    pub housekeeping_thread_started: bool,
    protocol: AutomapProtocol,
    find_routers_results: RefCell<Vec<Result<Vec<IpAddr>, AutomapError>>>,
    get_multicast_info_result: RefCell<MulticastInfo>,
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
            get_multicast_info_result: RefCell::new(MulticastInfo::new(
                IpAddr::from_str("0.0.0.0").unwrap(),
                0,
                0,
            )),
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

    pub fn get_multicast_info_result(self, result: MulticastInfo) -> Self {
        self.get_multicast_info_result.replace(result);
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

pub fn await_value<F, T, E>(
    interval_and_limit_ms: Option<(u64, u64)>,
    mut f: F,
) -> Result<T, String>
where
    E: Debug,
    F: FnMut() -> Result<T, E>,
{
    let (interval_ms, limit_ms) = interval_and_limit_ms.unwrap_or((250, 1000));
    let interval_dur = Duration::from_millis(interval_ms);
    let deadline = Instant::now() + Duration::from_millis(limit_ms);
    let mut delay = 0;
    let mut log = "".to_string();
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "\n{}\nTimeout: waited for more than {}ms",
                log, limit_ms
            ));
        }
        match f() {
            Ok(t) => return Ok(t),
            Err(e) => {
                log.extend(format!("  +{}: {:?}\n", delay, e).chars());
                delay += interval_ms;
                thread::sleep(interval_dur);
            }
        }
    }
}

pub fn make_change_handler_expecting_new_ip() -> (ChangeHandler, Arc<Mutex<Option<IpAddr>>>) {
    let received_ip_arc: Arc<Mutex<Option<IpAddr>>> = Arc::new(Mutex::new(None));
    let inner_received_ip = received_ip_arc.clone();
    let change_handler: ChangeHandler = Box::new(move |msg| {
        match msg {
            AutomapChange::NewIp(ip_addr) => inner_received_ip.lock().unwrap().replace(ip_addr),
            _ => None,
        };
    });
    (change_handler, received_ip_arc)
}

pub fn make_change_handler_expecting_error() -> (ChangeHandler, Arc<Mutex<Option<AutomapError>>>) {
    let received_error_arc: Arc<Mutex<Option<AutomapError>>> = Arc::new(Mutex::new(None));
    let inner_received_error = received_error_arc.clone();
    let change_handler: ChangeHandler = Box::new(move |msg| {
        match msg {
            AutomapChange::Error(error) => inner_received_error.lock().unwrap().replace(error),
            _ => None,
        };
    });
    (change_handler, received_error_arc)
}
