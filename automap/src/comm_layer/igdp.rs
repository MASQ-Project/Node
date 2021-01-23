// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::{Transactor, AutomapError};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use igd::{SearchOptions, Gateway, SearchError, GetExternalIpError, AddPortError, PortMappingProtocol, RemovePortError, search_gateway};
use std::cell::RefCell;

trait IgdWrapper {
    fn search_gateway(&self, options: SearchOptions) -> Result<Gateway, SearchError>;
    fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError>;
    fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError>;
    fn remove_port(&self, protocol: PortMappingProtocol, external_port: u16) -> Result<(), RemovePortError>;
}

struct IgdWrapperReal {
    delegate: RefCell<Option<Gateway>>,
}

impl IgdWrapper for IgdWrapperReal {
    fn search_gateway(&self, options: SearchOptions) -> Result<Gateway, SearchError> {
        let gateway = search_gateway(options)?;
        self.delegate.borrow_mut().replace (gateway.clone());
        Ok (gateway)
    }

    fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
        self.delegate.borrow().as_ref().expect ("Call search_gateway() first to establish a gateway")
            .get_external_ip()
    }

    fn add_port(&self, protocol: PortMappingProtocol, external_port: u16, local_addr: SocketAddrV4, lease_duration: u32, description: &str) -> Result<(), AddPortError> {
        self.delegate.borrow().as_ref().expect ("Call search_gateway() first to establish a gateway")
            .add_port (protocol, external_port, local_addr, lease_duration, description)
    }

    fn remove_port(&self, protocol: PortMappingProtocol, external_port: u16) -> Result<(), RemovePortError> {
        self.delegate.borrow().as_ref().expect ("Call search_gateway() first to establish a gateway")
            .remove_port (protocol, external_port)
    }
}

impl IgdWrapperReal {
    fn new () -> Self {
        Self {
            delegate: RefCell::new (None),
        }
    }
}

pub struct IgdpTransactor {

}

impl Transactor for IgdpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        unimplemented!()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        unimplemented!()
    }

    fn add_mapping(&self, router_ip: IpAddr, hole_port: u16, lifetime: u32) -> Result<u32, AutomapError> {
        unimplemented!()
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        unimplemented!()
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, Arc};

    struct IgdWrapperMock {
        search_gateway_params: Arc<Mutex<Vec<SearchOptions>>>,
        search_gateway_results: RefCell<Vec<Result<Gateway, SearchError>>>,
        get_external_ip_results: RefCell<Vec<Result<Ipv4Addr, GetExternalIpError>>>,
        add_port_params: Arc<Mutex<Vec<(PortMappingProtocol, u16, SocketAddrV4, u32, String)>>>,
        add_port_results: RefCell<Vec<Result<(), AddPortError>>>,
        remove_port_params: Arc<Mutex<Vec<(PortMappingProtocol, u16)>>>,
        remove_port_results: RefCell<Vec<Result<(), RemovePortError>>>,
    }

    impl IgdWrapper for IgdWrapperMock {
        fn search_gateway(&self, options: SearchOptions) -> Result<Gateway, SearchError> {
            self.search_gateway_params.lock().unwrap().push (options);
            self.search_gateway_results.borrow_mut().remove (0)
        }

        fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
            self.get_external_ip_results.borrow_mut().remove (0)
        }

        fn add_port(&self, protocol: PortMappingProtocol, external_port: u16, local_addr: SocketAddrV4, lease_duration: u32, description: &str) -> Result<(), AddPortError> {
            self.add_port_params.lock().unwrap().push ((protocol, external_port, local_addr, lease_duration, description.to_string()));
            self.add_port_results.borrow_mut().remove (0)
        }

        fn remove_port(&self, protocol: PortMappingProtocol, external_port: u16) -> Result<(), RemovePortError> {
            self.remove_port_params.lock().unwrap().push ((protocol, external_port));
            self.remove_port_results.borrow_mut().remove (0)
        }
    }

    impl IgdWrapperMock {
        pub fn new () -> Self {
            Self {
                search_gateway_params: Arc::new(Mutex::new(vec![])),
                search_gateway_results: RefCell::new(vec![]),
                get_external_ip_results: RefCell::new(vec![]),
                add_port_params: Arc::new(Mutex::new(vec![])),
                add_port_results: RefCell::new(vec![]),
                remove_port_params: Arc::new(Mutex::new(vec![])),
                remove_port_results: RefCell::new(vec![])
            }
        }

        pub fn search_gateway_params (mut self, params: &Arc<Mutex<Vec<SearchOptions>>>) -> Self {
            self.search_gateway_params = params.clone();
            self
        }

        pub fn search_gateway_result (self, result: Result<Gateway, SearchError>) -> Self {
            self.search_gateway_results.borrow_mut().push (result);
            self
        }

        pub fn get_external_ip_result (self, result: Result<Ipv4Addr, GetExternalIpError>) -> Self {
            self.get_external_ip_results.borrow_mut().push (result);
            self
        }

        pub fn add_port_params (mut self, params: &Arc<Mutex<Vec<(PortMappingProtocol, u16, SocketAddrV4, u32, String)>>>) -> Self {
            self.add_port_params = params.clone();
            self
        }

        pub fn add_port_result (self, result: Result<(), AddPortError>) -> Self {
            self.add_port_results.borrow_mut().push (result);
            self
        }

        pub fn remove_port_params (mut self, params: &Arc<Mutex<Vec<(PortMappingProtocol, u16)>>>) -> Self {
            self.remove_port_params = params.clone();
            self
        }

        pub fn remove_port_result (self, result: Result<(), RemovePortError>) -> Self {
            self.remove_port_results.borrow_mut().push (result);
            self
        }
    }

    #[test]
    fn nothing() {

    }
}
