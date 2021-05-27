// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::{AutomapError, LocalIpFinder, LocalIpFinderReal, Transactor};
use crate::control_layer::automap_control::ChangeHandler;
use igd::{
    search_gateway, AddPortError, Gateway, GetExternalIpError, PortMappingProtocol,
    RemovePortError, SearchError, SearchOptions,
};
use masq_lib::utils::AutomapProtocol;
use std::any::Any;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

trait GatewayFactory {
    fn make(&self, options: SearchOptions) -> Result<Box<dyn GatewayWrapper>, SearchError>;
}

struct GatewayFactoryReal {}

impl GatewayFactory for GatewayFactoryReal {
    fn make(&self, options: SearchOptions) -> Result<Box<dyn GatewayWrapper>, SearchError> {
        Ok(Box::new(GatewayWrapperReal::new(search_gateway(options)?)))
    }
}

impl GatewayFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

trait GatewayWrapper {
    fn get_gateway_addr(&self) -> SocketAddrV4;
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

struct GatewayWrapperReal {
    delegate: Gateway,
}

impl GatewayWrapper for GatewayWrapperReal {
    fn get_gateway_addr(&self) -> SocketAddrV4 {
        self.delegate.addr
    }

    fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
        self.delegate.get_external_ip()
    }

    fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> Result<(), AddPortError> {
        self.delegate.add_port(
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
        self.delegate.remove_port(protocol, external_port)
    }
}

impl GatewayWrapperReal {
    fn new(delegate: Gateway) -> Self {
        Self { delegate }
    }
}

pub struct IgdpTransactor {
    gateway_factory: Box<dyn GatewayFactory>,
    gateway: RefCell<Option<Box<dyn GatewayWrapper>>>,
    local_ip_finder: Box<dyn LocalIpFinder>,
}

impl Transactor for IgdpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        self.ensure_gateway()?;
        Ok(vec![IpAddr::V4(
            *self
                .gateway
                .borrow()
                .as_ref()
                .expect("ensure_gateway didn't work")
                .get_gateway_addr()
                .ip(),
        )])
    }

    fn get_public_ip(&self, _router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        self.ensure_gateway()?;
        match self
            .gateway
            .borrow()
            .as_ref()
            .expect("Must get Gateway before using it")
            .as_ref()
            .get_external_ip()
        {
            Ok(ip) => Ok(IpAddr::V4(ip)),
            Err(e) => Err(AutomapError::GetPublicIpError(format!("{:?}", e))),
        }
    }

    fn add_mapping(
        &self,
        _router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        self.ensure_gateway()?;
        let local_ip = match self.local_ip_finder.find()? {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => return Err(AutomapError::IPv6Unsupported(ip)),
        };
        match self
            .gateway
            .borrow()
            .as_ref()
            .expect("Must get Gateway before using it")
            .as_ref()
            .add_port(
                PortMappingProtocol::TCP,
                hole_port,
                SocketAddrV4::new(local_ip, hole_port),
                lifetime,
                "",
            ) {
            Ok(_) => Ok(lifetime / 2), // TODO For lifetime == 0, return a really big number instead
            Err(e)
                if (&format!("{:?}", e) == "OnlyPermanentLeasesSupported")
                    || (&format!("{:?}", e)
                        == "RequestError(ErrorCode(402, \"Invalid Args\"))") =>
            {
                Err(AutomapError::PermanentLeasesOnly)
            }
            Err(e) => Err(AutomapError::AddMappingError(format!("{:?}", e))),
        }
    }

    fn add_permanent_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
    ) -> Result<u32, AutomapError> {
        self.add_mapping(router_ip, hole_port, 0)
    }

    fn delete_mapping(&self, _router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        self.ensure_gateway()?;
        match self
            .gateway
            .borrow()
            .as_ref()
            .expect("Must get Gateway before using it")
            .as_ref()
            .remove_port(PortMappingProtocol::TCP, hole_port)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(AutomapError::DeleteMappingError(format!("{:?}", e))),
        }
    }

    fn protocol(&self) -> AutomapProtocol {
        AutomapProtocol::Igdp
    }

    fn start_change_handler(&mut self, _change_handler: ChangeHandler) -> Result<(), AutomapError> {
        todo!()
    }

    fn stop_change_handler(&mut self) {
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for IgdpTransactor {
    fn default() -> Self {
        Self::new()
    }
}

impl IgdpTransactor {
    pub fn new() -> Self {
        Self {
            gateway_factory: Box::new(GatewayFactoryReal::new()),
            gateway: RefCell::new(None),
            local_ip_finder: Box::new(LocalIpFinderReal::new()),
        }
    }

    fn ensure_gateway(&self) -> Result<(), AutomapError> {
        if self.gateway.borrow().is_some() {
            return Ok(());
        }
        let gateway = match self.gateway_factory.make(SearchOptions::default()) {
            Ok(g) => g,
            Err(_) => return Err(AutomapError::CantFindDefaultGateway),
        };
        self.gateway.borrow_mut().replace(gateway);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::tests::LocalIpFinderMock;
    use masq_lib::utils::AutomapProtocol;
    use std::net::Ipv6Addr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    struct GatewayFactoryMock {
        make_params: Arc<Mutex<Vec<SearchOptions>>>,
        make_results: RefCell<Vec<Result<GatewayWrapperMock, SearchError>>>,
    }

    impl GatewayFactory for GatewayFactoryMock {
        fn make(&self, options: SearchOptions) -> Result<Box<dyn GatewayWrapper>, SearchError> {
            self.make_params.lock().unwrap().push(options);
            match self.make_results.borrow_mut().remove(0) {
                Err(e) => Err(e),
                Ok(mock) => Ok(Box::new(mock)),
            }
        }
    }

    impl GatewayFactoryMock {
        fn new() -> Self {
            Self {
                make_params: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        fn make_params(mut self, params: &Arc<Mutex<Vec<SearchOptions>>>) -> Self {
            self.make_params = params.clone();
            self
        }

        fn make_result(self, result: Result<GatewayWrapperMock, SearchError>) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    struct GatewayWrapperMock {
        get_gateway_addr_results: RefCell<Vec<SocketAddrV4>>,
        get_external_ip_results: RefCell<Vec<Result<Ipv4Addr, GetExternalIpError>>>,
        add_port_params: Arc<Mutex<Vec<(PortMappingProtocol, u16, SocketAddrV4, u32, String)>>>,
        add_port_results: RefCell<Vec<Result<(), AddPortError>>>,
        remove_port_params: Arc<Mutex<Vec<(PortMappingProtocol, u16)>>>,
        remove_port_results: RefCell<Vec<Result<(), RemovePortError>>>,
    }

    impl GatewayWrapper for GatewayWrapperMock {
        fn get_gateway_addr(&self) -> SocketAddrV4 {
            self.get_gateway_addr_results.borrow_mut().remove(0)
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

    impl GatewayWrapperMock {
        fn new() -> Self {
            Self {
                get_gateway_addr_results: RefCell::new(vec![]),
                get_external_ip_results: RefCell::new(vec![]),
                add_port_params: Arc::new(Mutex::new(vec![])),
                add_port_results: RefCell::new(vec![]),
                remove_port_params: Arc::new(Mutex::new(vec![])),
                remove_port_results: RefCell::new(vec![]),
            }
        }

        fn get_gateway_addr_result(self, result: SocketAddrV4) -> Self {
            self.get_gateway_addr_results.borrow_mut().push(result);
            self
        }

        fn get_external_ip_result(self, result: Result<Ipv4Addr, GetExternalIpError>) -> Self {
            self.get_external_ip_results.borrow_mut().push(result);
            self
        }

        fn add_port_params(
            mut self,
            params: &Arc<Mutex<Vec<(PortMappingProtocol, u16, SocketAddrV4, u32, String)>>>,
        ) -> Self {
            self.add_port_params = params.clone();
            self
        }

        fn add_port_result(self, result: Result<(), AddPortError>) -> Self {
            self.add_port_results.borrow_mut().push(result);
            self
        }

        fn remove_port_params(
            mut self,
            params: &Arc<Mutex<Vec<(PortMappingProtocol, u16)>>>,
        ) -> Self {
            self.remove_port_params = params.clone();
            self
        }

        fn remove_port_result(self, result: Result<(), RemovePortError>) -> Self {
            self.remove_port_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn knows_its_method() {
        let subject = IgdpTransactor::new();

        let method = subject.protocol();

        assert_eq!(method, AutomapProtocol::Igdp);
    }

    #[test]
    fn find_routers_works() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway_addr = SocketAddrV4::from_str("192.168.0.1:1900").unwrap();
        let gateway = GatewayWrapperMock::new().get_gateway_addr_result(gateway_addr);
        let gateway_factory = GatewayFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.find_routers().unwrap();

        assert_eq!(result, vec![IpAddr::V4(gateway_addr.ip().clone())]);
        let make_params = make_params_arc.lock().unwrap();
        let actual_search_options = &make_params[0];
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
    fn find_routers_handles_error() {
        let gateway_factory =
            GatewayFactoryMock::new().make_result(Err(SearchError::InvalidResponse));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.find_routers();

        assert_eq!(result, Err(AutomapError::CantFindDefaultGateway));
    }

    #[test]
    fn get_public_ip_works() {
        let public_ipv4 = Ipv4Addr::from_str("72.73.74.75").unwrap();
        let public_ip = IpAddr::V4(public_ipv4);
        let gateway = GatewayWrapperMock::new().get_external_ip_result(Ok(public_ipv4));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject
            .get_public_ip(IpAddr::from_str("192.168.0.1").unwrap())
            .unwrap();

        assert_eq!(result, public_ip);
    }

    #[test]
    fn get_public_ip_handles_error() {
        let gateway = GatewayWrapperMock::new()
            .get_external_ip_result(Err(GetExternalIpError::ActionNotAuthorized));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.get_public_ip(IpAddr::from_str("192.168.0.1").unwrap());

        assert_eq!(
            result,
            Err(AutomapError::GetPublicIpError(
                "ActionNotAuthorized".to_string()
            ))
        );
    }

    #[test]
    fn add_mapping_works() {
        let local_ipv4 = Ipv4Addr::from_str("192.168.0.101").unwrap();
        let local_ip = IpAddr::V4(local_ipv4);
        let add_port_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = GatewayWrapperMock::new()
            .add_port_params(&add_port_params_arc)
            .add_port_result(Ok(()));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject
            .add_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777, 1234)
            .unwrap();

        assert_eq!(result, 617);
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
    fn add_permanent_mapping_works() {
        let local_ipv4 = Ipv4Addr::from_str("192.168.0.101").unwrap();
        let local_ip = IpAddr::V4(local_ipv4);
        let add_port_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = GatewayWrapperMock::new()
            .add_port_params(&add_port_params_arc)
            .add_port_result(Ok(()));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject
            .add_permanent_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777)
            .unwrap();

        assert_eq!(result, u32::MAX);
        let add_port_params = add_port_params_arc.lock().unwrap();
        assert_eq!(
            *add_port_params,
            vec![(
                PortMappingProtocol::TCP,
                7777,
                SocketAddrV4::new(local_ipv4, 7777),
                0,
                "".to_string(),
            )]
        );
    }

    #[test]
    fn add_mapping_handles_ipv6_local_address() {
        let local_ipv6 = Ipv6Addr::from_str("0000:1111:2222:3333:4444:5555:6666:7777").unwrap();
        let gateway = GatewayWrapperMock::new().add_port_result(Ok(()));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(IpAddr::V6(local_ipv6)));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777, 1234);

        assert_eq!(result, Err(AutomapError::IPv6Unsupported(local_ipv6)));
    }

    #[test]
    fn add_mapping_handles_only_permanent_lease_error() {
        let local_ip = IpAddr::from_str("192.168.0.101").unwrap();
        let gateway = GatewayWrapperMock::new()
            .add_port_result(Err(AddPortError::OnlyPermanentLeasesSupported));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777, 1234);

        assert_eq!(result, Err(AutomapError::PermanentLeasesOnly));
    }

    #[test]
    fn add_mapping_handles_other_error() {
        let local_ip = IpAddr::from_str("192.168.0.101").unwrap();
        let gateway = GatewayWrapperMock::new().add_port_result(Err(AddPortError::PortInUse));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::AddMappingError("PortInUse".to_string()))
        );
    }

    #[test]
    fn delete_mapping_works() {
        let remove_port_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = GatewayWrapperMock::new()
            .remove_port_params(&remove_port_params_arc)
            .remove_port_result(Ok(()));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let _ = subject
            .delete_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777)
            .unwrap();

        let remove_port_params = remove_port_params_arc.lock().unwrap();
        assert_eq!(*remove_port_params, vec![(PortMappingProtocol::TCP, 7777,)]);
    }

    #[test]
    fn delete_mapping_handles_error() {
        let gateway =
            GatewayWrapperMock::new().remove_port_result(Err(RemovePortError::NoSuchPortMapping));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.delete_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777);

        assert_eq!(
            result,
            Err(AutomapError::DeleteMappingError(
                "NoSuchPortMapping".to_string()
            ))
        );
    }

    #[test]
    fn ensure_gateway_handles_missing_gateway() {
        let gateway_factory =
            GatewayFactoryMock::new().make_result(Err(SearchError::InvalidResponse));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.ensure_gateway();

        assert_eq!(result, Err(AutomapError::CantFindDefaultGateway));
    }
}
