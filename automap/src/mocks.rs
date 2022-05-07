// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(any(test, not(feature = "no_test_share")))]

use crate::comm_layer::pcp_pmp_common::{
    FindRoutersCommand, FreePortFactory, UdpSocketWrapper, UdpSocketWrapperFactory,
};
use crate::comm_layer::{AutomapError, HousekeepingThreadCommand, LocalIpFinder, Transactor};
use crate::control_layer::automap_control::{
    replace_transactor, AutomapControlReal, ChangeHandler,
};
use crossbeam_channel::Sender;
use lazy_static::lazy_static;
use masq_lib::utils::AutomapProtocol;
use std::any::Any;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
}

impl UdpSocketWrapperMock {
    #[allow(clippy::new_without_default)]
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

pub fn pmp_protocol_scenario_for_actor_system_factory_test(
    sender: Sender<HousekeepingThreadCommand>,
) -> AutomapControlReal {
    let change_handler = Box::new(|_| ());
    let subject = AutomapControlReal::new(None, change_handler);
    let pcp_mock = TransactorMock::new(AutomapProtocol::Pcp).find_routers_result(Ok(vec![]));
    let pmp_mock = TransactorMock::new(AutomapProtocol::Pmp)
        .find_routers_result(Ok(vec![*ROUTER_IP]))
        .start_housekeeping_thread_result(Ok(sender))
        .stop_housekeeping_thread_result(Ok(Box::new(|_| ())))
        .get_public_ip_result(Ok(*PUBLIC_IP))
        .add_mapping_result(Ok(1000));
    let subject = replace_transactor(subject, Box::new(pcp_mock));
    replace_transactor(subject, Box::new(pmp_mock))
}
