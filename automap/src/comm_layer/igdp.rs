// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::{AutomapError, Transactor};
use igd::{
    search_gateway, AddPortError, Gateway, GetExternalIpError, PortMappingProtocol,
    RemovePortError, SearchError, SearchOptions,
};
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

trait IgdWrapper {
    fn search_gateway(&self, options: SearchOptions) -> Result<Gateway, SearchError>;
    fn get_gateway(&self) -> Option<Gateway>;
    fn set_gateway(&self, gateway: Gateway);
    fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError>;
    fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError>;
    fn remove_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
    ) -> Result<(), RemovePortError>;
}

struct IgdWrapperReal {
    delegate: RefCell<Option<Gateway>>,
}

impl IgdWrapper for IgdWrapperReal {
    fn search_gateway(&self, options: SearchOptions) -> Result<Gateway, SearchError> {
        let gateway = search_gateway(options)?;
        self.delegate.borrow_mut().replace(gateway.clone());
        Ok(gateway)
    }

    fn get_gateway(&self) -> Option<Gateway> {
        self.delegate.borrow().clone()
    }

    fn set_gateway(&self, gateway: Gateway) {
        self.delegate.borrow_mut().replace(gateway);
    }

    fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
        self.delegate
            .borrow()
            .as_ref()
            .expect("Call search_gateway() first to establish a gateway")
            .get_external_ip()
    }

    fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError> {
        self.delegate
            .borrow()
            .as_ref()
            .expect("Call search_gateway() first to establish a gateway")
            .add_port(
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description,
            )
    }

    fn remove_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
    ) -> Result<(), RemovePortError> {
        self.delegate
            .borrow()
            .as_ref()
            .expect("Call search_gateway() first to establish a gateway")
            .remove_port(protocol, external_port)
    }
}

impl IgdWrapperReal {
    fn new() -> Self {
        Self {
            delegate: RefCell::new(None),
        }
    }
}

pub struct IgdpTransactor {
    igd_wrapper: Box<dyn IgdWrapper>,
}

impl Transactor for IgdpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        let gateway = match self.igd_wrapper.search_gateway(SearchOptions::default()) {
            Ok(gateway) => gateway,
            Err(e) => unimplemented!("{:?}", e),
        };
        Ok(vec![IpAddr::V4(gateway.addr.ip().clone())])
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        self.ensure_router_ip(router_ip)?;
        match self.igd_wrapper.get_external_ip() {
            Ok(ip) => Ok(IpAddr::V4(ip)),
            Err(e) => unimplemented!("{:?}", e),
        }
    }

    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        self.ensure_router_ip(router_ip)?;
        match self.igd_wrapper.add_port(
            PortMappingProtocol::TCP,
            hole_port,
            SocketAddrV4::new(Self::local_ip()?, hole_port),
            lifetime,
            "",
        ) {
            Ok(ip) => Ok(lifetime / 2),
            Err(e) => unimplemented!("{:?}", e),
        }
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        self.ensure_router_ip(router_ip)?;
        match self
            .igd_wrapper
            .remove_port(PortMappingProtocol::TCP, hole_port)
        {
            Ok(ip) => Ok(()),
            Err(e) => unimplemented!("{:?}", e),
        }
    }
}

impl IgdpTransactor {
    pub fn new() -> Self {
        Self {
            igd_wrapper: Box::new(IgdWrapperReal::new()),
        }
    }

    fn ensure_router_ip(&self, router_ip: IpAddr) -> Result<(), AutomapError> {
        let router_ipv4 = match router_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => unimplemented!("{:?}", ip),
        };
        let mut gateway = match self.igd_wrapper.get_gateway() {
            Some(g) => g,
            None => unimplemented!(),
        };
        gateway.addr = SocketAddrV4::new(router_ipv4, 1900);
        self.igd_wrapper.set_gateway(gateway);
        Ok(())
    }

    fn local_ip() -> Result<Ipv4Addr, AutomapError> {
        match local_ipaddress::get() {
            Some(ip_str) => match Ipv4Addr::from_str(&ip_str) {
                Ok(ip) => Ok(ip),
                Err(e) => unimplemented!("{:?}", e),
            },
            None => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::pcp_pmp_common::mocks::UdpSocketFactoryMock;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    struct IgdWrapperMock {
        search_gateway_params: Arc<Mutex<Vec<SearchOptions>>>,
        search_gateway_results: RefCell<Vec<Result<Gateway, SearchError>>>,
        get_gateway_results: RefCell<Vec<Option<Gateway>>>,
        set_gateway_params: Arc<Mutex<Vec<Gateway>>>,
        get_external_ip_results: RefCell<Vec<Result<Ipv4Addr, GetExternalIpError>>>,
        add_port_params: Arc<Mutex<Vec<(PortMappingProtocol, u16, SocketAddrV4, u32, String)>>>,
        add_port_results: RefCell<Vec<Result<(), AddPortError>>>,
        remove_port_params: Arc<Mutex<Vec<(PortMappingProtocol, u16)>>>,
        remove_port_results: RefCell<Vec<Result<(), RemovePortError>>>,
    }

    impl IgdWrapper for IgdWrapperMock {
        fn search_gateway(&self, options: SearchOptions) -> Result<Gateway, SearchError> {
            self.search_gateway_params.lock().unwrap().push(options);
            self.search_gateway_results.borrow_mut().remove(0)
        }

        fn get_gateway(&self) -> Option<Gateway> {
            self.get_gateway_results.borrow_mut().remove(0)
        }

        fn set_gateway(&self, gateway: Gateway) {
            self.set_gateway_params.lock().unwrap().push(gateway);
        }

        fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
            self.get_external_ip_results.borrow_mut().remove(0)
        }

        fn add_port(
            &self,
            protocol: PortMappingProtocol,
            external_port: u16,
            local_addr: SocketAddrV4,
            lease_duration: u32,
            description: &str,
        ) -> Result<(), AddPortError> {
            self.add_port_params.lock().unwrap().push((
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description.to_string(),
            ));
            self.add_port_results.borrow_mut().remove(0)
        }

        fn remove_port(
            &self,
            protocol: PortMappingProtocol,
            external_port: u16,
        ) -> Result<(), RemovePortError> {
            self.remove_port_params
                .lock()
                .unwrap()
                .push((protocol, external_port));
            self.remove_port_results.borrow_mut().remove(0)
        }
    }

    impl IgdWrapperMock {
        pub fn new() -> Self {
            Self {
                search_gateway_params: Arc::new(Mutex::new(vec![])),
                search_gateway_results: RefCell::new(vec![]),
                get_gateway_results: RefCell::new(vec![]),
                set_gateway_params: Arc::new(Mutex::new(vec![])),
                get_external_ip_results: RefCell::new(vec![]),
                add_port_params: Arc::new(Mutex::new(vec![])),
                add_port_results: RefCell::new(vec![]),
                remove_port_params: Arc::new(Mutex::new(vec![])),
                remove_port_results: RefCell::new(vec![]),
            }
        }

        pub fn search_gateway_params(mut self, params: &Arc<Mutex<Vec<SearchOptions>>>) -> Self {
            self.search_gateway_params = params.clone();
            self
        }

        pub fn search_gateway_result(self, result: Result<Gateway, SearchError>) -> Self {
            self.search_gateway_results.borrow_mut().push(result);
            self
        }

        pub fn get_gateway_result(self, result: Option<Gateway>) -> Self {
            self.get_gateway_results.borrow_mut().push(result);
            self
        }

        pub fn set_gateway_params(mut self, params: &Arc<Mutex<Vec<Gateway>>>) -> Self {
            self.set_gateway_params = params.clone();
            self
        }

        pub fn get_external_ip_result(self, result: Result<Ipv4Addr, GetExternalIpError>) -> Self {
            self.get_external_ip_results.borrow_mut().push(result);
            self
        }

        pub fn add_port_params(
            mut self,
            params: &Arc<Mutex<Vec<(PortMappingProtocol, u16, SocketAddrV4, u32, String)>>>,
        ) -> Self {
            self.add_port_params = params.clone();
            self
        }

        pub fn add_port_result(self, result: Result<(), AddPortError>) -> Self {
            self.add_port_results.borrow_mut().push(result);
            self
        }

        pub fn remove_port_params(
            mut self,
            params: &Arc<Mutex<Vec<(PortMappingProtocol, u16)>>>,
        ) -> Self {
            self.remove_port_params = params.clone();
            self
        }

        pub fn remove_port_result(self, result: Result<(), RemovePortError>) -> Self {
            self.remove_port_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn find_routers_works() {
        let search_gateway_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = Gateway {
            addr: SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 1900),
            root_url: "root_url".to_string(),
            control_url: "control_url".to_string(),
            control_schema_url: "control_schema_url".to_string(),
            control_schema: HashMap::default(),
        };
        let igd_wrapper = IgdWrapperMock::new()
            .search_gateway_params(&search_gateway_params_arc)
            .search_gateway_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.igd_wrapper = Box::new(igd_wrapper);

        let result = subject.find_routers().unwrap();

        assert_eq!(result, vec![IpAddr::from_str("192.168.0.1").unwrap()]);
        let search_gateway_params = search_gateway_params_arc.lock().unwrap();
        let actual_search_options = &search_gateway_params[0];
        let expected_search_options = SearchOptions::default();
        assert_eq!(
            actual_search_options.bind_addr,
            expected_search_options.bind_addr
        );
        assert_eq!(
            actual_search_options.broadcast_address,
            expected_search_options.broadcast_address
        );
        assert_eq!(
            actual_search_options.timeout,
            expected_search_options.timeout
        );
    }

    #[test]
    fn get_public_ip_works() {
        let router_ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let router_ip = IpAddr::V4(router_ipv4);
        let public_ipv4 = Ipv4Addr::from_str("72.73.74.75").unwrap();
        let public_ip = IpAddr::V4(public_ipv4);
        let set_gateway_params_arc = Arc::new(Mutex::new(vec![]));
        let initial_gateway = Gateway {
            addr: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5),
            root_url: "root_url".to_string(),
            control_url: "control_url".to_string(),
            control_schema_url: "control_schema_url".to_string(),
            control_schema: HashMap::default(),
        };
        let mut final_gateway = initial_gateway.clone();
        final_gateway.addr = SocketAddrV4::new(router_ipv4, 1900);
        let igd_wrapper = IgdWrapperMock::new()
            .get_gateway_result(Some(initial_gateway))
            .set_gateway_params(&set_gateway_params_arc)
            .get_external_ip_result(Ok(public_ipv4));
        let mut subject = IgdpTransactor::new();
        subject.igd_wrapper = Box::new(igd_wrapper);

        let result = subject.get_public_ip(router_ip).unwrap();

        assert_eq!(result, public_ip);
        let set_gateway_params = set_gateway_params_arc.lock().unwrap();
        let actual_gateway = &set_gateway_params[0];
        assert_eq!(actual_gateway.addr, SocketAddrV4::new(router_ipv4, 1900));
    }

    #[test]
    fn add_mapping_works() {
        let router_ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let router_ip = IpAddr::V4(router_ipv4);
        let local_ipv4 = Ipv4Addr::from_str(&local_ipaddress::get().unwrap()).unwrap();
        let set_gateway_params_arc = Arc::new(Mutex::new(vec![]));
        let add_port_params_arc = Arc::new(Mutex::new(vec![]));
        let initial_gateway = Gateway {
            addr: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5),
            root_url: "root_url".to_string(),
            control_url: "control_url".to_string(),
            control_schema_url: "control_schema_url".to_string(),
            control_schema: HashMap::default(),
        };
        let mut final_gateway = initial_gateway.clone();
        final_gateway.addr = SocketAddrV4::new(router_ipv4, 1900);
        let igd_wrapper = IgdWrapperMock::new()
            .get_gateway_result(Some(initial_gateway))
            .set_gateway_params(&set_gateway_params_arc)
            .add_port_params(&add_port_params_arc)
            .add_port_result(Ok(()));
        let mut subject = IgdpTransactor::new();
        subject.igd_wrapper = Box::new(igd_wrapper);

        let result = subject.add_mapping(router_ip, 7777, 1234).unwrap();

        assert_eq!(result, 617);
        let set_gateway_params = set_gateway_params_arc.lock().unwrap();
        let actual_gateway = &set_gateway_params[0];
        assert_eq!(actual_gateway.addr, SocketAddrV4::new(router_ipv4, 1900));
        let add_port_params = add_port_params_arc.lock().unwrap();
        assert_eq!(
            *add_port_params,
            vec![(
                PortMappingProtocol::TCP,
                7777,
                SocketAddrV4::new(local_ipv4, 7777),
                1234,
                "".to_string(),
            )]
        );
    }

    #[test]
    fn delete_mapping_works() {
        let router_ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let router_ip = IpAddr::V4(router_ipv4);
        let local_ipv4 = Ipv4Addr::from_str(&local_ipaddress::get().unwrap()).unwrap();
        let set_gateway_params_arc = Arc::new(Mutex::new(vec![]));
        let remove_port_params_arc = Arc::new(Mutex::new(vec![]));
        let initial_gateway = Gateway {
            addr: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5),
            root_url: "root_url".to_string(),
            control_url: "control_url".to_string(),
            control_schema_url: "control_schema_url".to_string(),
            control_schema: HashMap::default(),
        };
        let mut final_gateway = initial_gateway.clone();
        final_gateway.addr = SocketAddrV4::new(router_ipv4, 1900);
        let igd_wrapper = IgdWrapperMock::new()
            .get_gateway_result(Some(initial_gateway))
            .set_gateway_params(&set_gateway_params_arc)
            .remove_port_params(&remove_port_params_arc)
            .remove_port_result(Ok(()));
        let mut subject = IgdpTransactor::new();
        subject.igd_wrapper = Box::new(igd_wrapper);

        let _ = subject.delete_mapping(router_ip, 7777).unwrap();

        let set_gateway_params = set_gateway_params_arc.lock().unwrap();
        let actual_gateway = &set_gateway_params[0];
        assert_eq!(actual_gateway.addr, SocketAddrV4::new(router_ipv4, 1900));
        let remove_port_params = remove_port_params_arc.lock().unwrap();
        assert_eq!(*remove_port_params, vec![(PortMappingProtocol::TCP, 7777,)]);
    }
}
