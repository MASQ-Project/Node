// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::HousekeeperConfig;
use crate::comm_layer::{
    AutomapError, HousekeepingThreadCommand, LocalIpFinder, LocalIpFinderReal, Transactor,
    DEFAULT_MAPPING_LIFETIME_SECONDS,
};
use crate::control_layer::automap_control::{AutomapChange, ChangeHandler};
use crossbeam_channel::{unbounded, Receiver, Sender};
use igd::{
    search_gateway, AddPortError, Gateway, GetExternalIpError, PortMappingProtocol,
    RemovePortError, SearchError, SearchOptions,
};
use masq_lib::debug;
use masq_lib::error;
use masq_lib::info;
use masq_lib::logger::Logger;
use masq_lib::utils::AutomapProtocol;
use masq_lib::warning;
use std::any::Any;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const PUBLIC_IP_POLL_DELAY_SECONDS: u32 = 60;

trait GatewayFactory {
    fn make(&self, options: SearchOptions) -> Result<Box<dyn GatewayWrapper>, SearchError>;
}

#[derive(Clone)]
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

trait GatewayWrapper: Send {
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

struct IgdpTransactorInner {
    gateway_opt: Option<Box<dyn GatewayWrapper>>,
    housekeeping_commander_opt: Option<Sender<HousekeepingThreadCommand>>,
    public_ip_opt: Option<Ipv4Addr>,
    mapping_adder: Box<dyn MappingAdder>,
    change_handler_config_opt: RefCell<Option<HousekeeperConfig>>,
    logger: Logger,
}

pub struct IgdpTransactor {
    gateway_factory: Box<dyn GatewayFactory>,
    public_ip_poll_delay_ms: u32,
    inner_arc: Arc<Mutex<IgdpTransactorInner>>,
    join_handle_opt: Option<JoinHandle<ChangeHandler>>,
}

impl Transactor for IgdpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        self.ensure_gateway()?;
        let inner = self.inner();
        debug!(inner.logger, "Seeking routers on LAN");
        Ok(vec![IpAddr::V4(
            *inner
                .gateway_opt
                .as_ref()
                .expect("ensure_gateway didn't work")
                .get_gateway_addr()
                .ip(),
        )])
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        self.ensure_gateway()?;
        let mut inner = self.inner_arc.lock().expect("Change handler died");
        debug!(
            inner.logger,
            "Seeking public IP from router at {}", router_ip
        );
        match inner
            .gateway_opt
            .as_ref()
            .expect("Must get Gateway before using it")
            .as_ref()
            .get_external_ip()
        {
            Ok(ip) => {
                inner.public_ip_opt.replace(ip);
                Ok(IpAddr::V4(ip))
            }
            Err(e) => {
                warning!(
                    inner.logger,
                    "WARN: IgdpTransactor: Error getting public IP from router at {}: \"{:?}\"",
                    router_ip,
                    e
                );
                Err(AutomapError::GetPublicIpError(format!("{:?}", e)))
            }
        }
    }

    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        self.ensure_gateway()?;
        let inner = self.inner_arc.lock().expect("Housekeeping thread is dead");
        debug!(
            inner.logger,
            "Adding mapping for port {} through router at {} for {} seconds",
            hole_port,
            router_ip,
            lifetime
        );
        let gateway = inner
            .gateway_opt
            .as_ref()
            .expect("Ensuring the gateway didn't work");
        inner
            .mapping_adder
            .add_mapping(gateway.as_ref(), hole_port, lifetime)
            .map(|remap_interval| {
                inner
                    .change_handler_config_opt
                    .replace(Some(HousekeeperConfig {
                        hole_port,
                        next_lifetime: Duration::from_secs(lifetime as u64),
                        remap_interval: Duration::from_secs(remap_interval as u64),
                    }));
                remap_interval
            })
    }

    fn add_permanent_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
    ) -> Result<u32, AutomapError> {
        self.add_mapping(router_ip, hole_port, 0).map(|_| u32::MAX)
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        self.ensure_gateway()?;
        let inner = self.inner_arc.lock().expect("Change handler is dead");
        debug!(
            inner.logger,
            "Deleting mapping of port {} through router at {}", hole_port, router_ip
        );
        match inner
            .gateway_opt
            .as_ref()
            .expect("Must get Gateway before using it")
            .as_ref()
            .remove_port(PortMappingProtocol::TCP, hole_port)
        {
            Ok(_) => Ok(()),
            Err(e) => {
                warning!(
                    inner.logger,
                    "Can't delete mapping of port {} through router at {}: \"{:?}\"",
                    hole_port,
                    router_ip,
                    e
                );
                Err(AutomapError::DeleteMappingError(format!("{:?}", e)))
            }
        }
    }

    fn protocol(&self) -> AutomapProtocol {
        AutomapProtocol::Igdp
    }

    fn start_housekeeping_thread(
        &mut self,
        change_handler: ChangeHandler,
        router_ip: IpAddr,
    ) -> Result<Sender<HousekeepingThreadCommand>, AutomapError> {
        let (tx, rx) = unbounded();
        let public_ip_poll_delay_ms = {
            let mut inner = self.inner_arc.lock().expect("Change handler is dead");
            if inner.housekeeping_commander_opt.is_some() {
                info!(
                    inner.logger,
                    "Change handler for router at {} is already running", router_ip
                );
                return Err(AutomapError::ChangeHandlerAlreadyRunning);
            }
            inner.housekeeping_commander_opt = Some(tx.clone());
            debug!(
                inner.logger,
                "Starting housekeeping thread for router at {}", router_ip
            );
            self.public_ip_poll_delay_ms
        };
        let inner_inner = self.inner_arc.clone();
        self.join_handle_opt = Some(thread::spawn(move || {
            Self::thread_guts(public_ip_poll_delay_ms, change_handler, inner_inner, rx)
        }));
        Ok(tx)
    }

    fn stop_housekeeping_thread(&mut self) -> ChangeHandler {
        let stopper = {
            let inner = self.inner_arc.lock().expect("Change handler is dead");
            debug!(inner.logger, "Stopping housekeeping thread");
            inner.housekeeping_commander_opt.clone()
        }
        .expect("No HousekeepingCommander: can't stop housekeeping thread");
        match stopper.try_send(HousekeepingThreadCommand::Stop) {
            Ok(_) => {
                let join_handle = self
                    .join_handle_opt
                    .take()
                    .expect("No JoinHandle: can't stop housekeeping thread");
                match join_handle.join() {
                    Ok(change_handler) => change_handler,
                    Err(_) => {
                        let inner = self.inner_arc.lock().expect("Change handler is dead");
                        warning!(
                            inner.logger,
                            "Tried to stop housekeeping thread that had panicked"
                        );
                        Box::new(Self::null_change_handler)
                    }
                }
            }
            Err(_) => {
                let inner = self.inner_arc.lock().expect("Change handler is dead");
                warning!(inner.logger, "Tried to stop housekeeping thread that had already disconnected from the commander");
                Box::new(Self::null_change_handler)
            }
        }
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
        let gateway_factory = Box::new(GatewayFactoryReal::new());
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: None,
            housekeeping_commander_opt: None,
            public_ip_opt: None,
            mapping_adder: Box::new(MappingAdderReal::new()),
            change_handler_config_opt: RefCell::new(None),
            logger: Logger::new("IgdpTransactor"),
        }));
        Self {
            gateway_factory,
            public_ip_poll_delay_ms: PUBLIC_IP_POLL_DELAY_SECONDS * 1000,
            inner_arc,
            join_handle_opt: None,
        }
    }

    fn ensure_gateway(&self) -> Result<(), AutomapError> {
        Self::ensure_gateway_static(&self.inner_arc, self.gateway_factory.as_ref())
    }

    fn ensure_gateway_static(
        inner_arc: &Arc<Mutex<IgdpTransactorInner>>,
        gateway_factory: &dyn GatewayFactory,
    ) -> Result<(), AutomapError> {
        let mut inner = inner_arc.lock().expect("Change handler is dead");
        if inner.gateway_opt.is_some() {
            return Ok(());
        }
        let gateway = match gateway_factory.make(SearchOptions::default()) {
            Ok(g) => g,
            Err(e) => {
                warning!(
                    inner.logger,
                    "Error locating routers on the LAN: \"{:?}\"",
                    e
                );
                return Err(AutomapError::CantFindDefaultGateway);
            }
        };
        inner.gateway_opt.replace(gateway);
        Ok(())
    }

    fn inner(&self) -> MutexGuard<IgdpTransactorInner> {
        self.inner_arc.lock().expect("Change handler died")
    }

    fn thread_guts(
        public_ip_poll_delay_ms: u32,
        change_handler: ChangeHandler,
        inner_arc: Arc<Mutex<IgdpTransactorInner>>,
        rx: Receiver<HousekeepingThreadCommand>,
    ) -> ChangeHandler {
        let mut last_remapped = Instant::now();
        let mut remap_interval = Duration::from_secs(DEFAULT_MAPPING_LIFETIME_SECONDS as u64);
        loop {
            thread::sleep(Duration::from_millis(public_ip_poll_delay_ms as u64));
            if !Self::thread_guts_iteration(
                &change_handler,
                &inner_arc,
                &mut last_remapped,
                remap_interval,
            ) {
                break;
            }
            match rx.try_recv() {
                Ok(HousekeepingThreadCommand::Stop) => break,
                Ok(HousekeepingThreadCommand::SetRemapIntervalMs(remap_after)) => {
                    remap_interval = Duration::from_millis(remap_after)
                }
                Err(_) => continue,
            }
        }
        return change_handler;
    }

    fn thread_guts_iteration(
        change_handler: &ChangeHandler,
        inner_arc: &Arc<Mutex<IgdpTransactorInner>>,
        last_remapped: &mut Instant,
        remap_interval: Duration,
    ) -> bool {
        let mut inner = inner_arc.lock().expect("IgdpTransactor died");
        debug!(
            inner.logger,
            "Polling router to see if public IP has changed"
        );
        let gateway_wrapper = match inner.gateway_opt.take() {
            Some(gw) => gw,
            None => {
                let _ = inner.housekeeping_commander_opt.take();
                error!(inner.logger, "Can't find router");
                change_handler(AutomapChange::Error(AutomapError::CantFindDefaultGateway));
                return false;
            }
        };
        let (old_public_ip, current_public_ip) = match Self::retrieve_old_and_new_public_ips(
            gateway_wrapper.as_ref(),
            &inner,
            change_handler,
        ) {
            Some(pair) => pair,
            None => {
                inner.gateway_opt.replace(gateway_wrapper);
                return true;
            }
        };
        if current_public_ip != old_public_ip {
            info!(
                inner.logger,
                "Public IP changed from {} to {}", current_public_ip, old_public_ip
            );
            inner.public_ip_opt.replace(current_public_ip);
            change_handler(AutomapChange::NewIp(IpAddr::V4(current_public_ip)));
        } else {
            debug!(
                inner.logger,
                "No public IP change detected; still {}", old_public_ip
            );
        };

        let since_last_remapped = last_remapped.elapsed();
        if since_last_remapped.gt(&remap_interval) {
            let chc_ref = inner.change_handler_config_opt.borrow();
            let change_handler_config = match &(*chc_ref) {
                Some(chc) => chc,
                None => {
                    return true;
                }
            };
            if let Err(e) = Self::remap_port(
                inner.mapping_adder.as_ref(),
                gateway_wrapper.as_ref(),
                change_handler_config.hole_port,
                change_handler_config.remap_interval,
                &inner.logger,
            ) {
                error!(inner.logger, "Remapping failure: {:?}", e);
                change_handler(AutomapChange::Error(e));
                return true;
            }
            *last_remapped = Instant::now();
        }
        inner.gateway_opt.replace(gateway_wrapper);
        true
    }

    fn null_change_handler(change: AutomapChange) {
        let logger = Logger::new("IgdpTransactor");
        error!(
            logger,
            "Change handler recovery failed: discarded {:?}", change
        );
    }

    fn retrieve_old_and_new_public_ips(
        gateway_wrapper: &dyn GatewayWrapper,
        inner: &IgdpTransactorInner,
        change_handler: &ChangeHandler,
    ) -> Option<(Ipv4Addr, Ipv4Addr)> {
        let current_public_ip_result = gateway_wrapper.get_external_ip();
        let (old_public_ip, current_public_ip) =
            match (inner.public_ip_opt, current_public_ip_result) {
                (_, Err(e)) => {
                    error!(
                        inner.logger,
                        "Change handler could not get public IP from router: {:?}", e
                    );
                    change_handler(AutomapChange::Error(AutomapError::GetPublicIpError(
                        format!("{:?}", e),
                    )));
                    return None;
                }
                (None, Ok(current)) => {
                    warning!(
                        inner.logger,
                        "Change handler was started before retrieving public IP"
                    );
                    (Ipv4Addr::new(0, 0, 0, 0), current)
                }
                (Some(old), Ok(current)) => (old, current),
            };
        Some((old_public_ip, current_public_ip))
    }

    fn remap_port(
        mapping_adder: &dyn MappingAdder,
        gateway: &dyn GatewayWrapper,
        hole_port: u16,
        requested_lifetime: Duration,
        logger: &Logger,
    ) -> Result<u32, AutomapError> {
        info!(logger, "Remapping port {}", hole_port);
        let mut requested_lifetime_secs = requested_lifetime.as_secs() as u32;
        if requested_lifetime_secs < 1 {
            requested_lifetime_secs = 1;
        }
        // No update to our ChangeHandlerConfig's lifetime is required here, because IGDP either
        // gives us the lifetime we request, or doesn't do the mapping at all. It never gives us
        // a mapping with a different lifetime from the one we request.
        mapping_adder.add_mapping(gateway, hole_port, requested_lifetime_secs)
    }
}

trait MappingAdder: Send {
    fn add_mapping(
        &self,
        gateway: &dyn GatewayWrapper,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError>;
}

struct MappingAdderReal {
    local_ip_finder: Box<dyn LocalIpFinder>,
    logger: Logger,
}

impl MappingAdder for MappingAdderReal {
    fn add_mapping(
        &self,
        gateway: &dyn GatewayWrapper,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        let local_ip = match self.local_ip_finder.find() {
            Err(e) => {
                warning!(
                    self.logger,
                    "Cannot determine local IP address: \"{:?}\"",
                    e
                );
                return Err(e);
            }
            Ok(ip) => match ip {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(ip) => {
                    warning!(
                        self.logger,
                        "IGDP is incompatible with an IPv6 local IP address"
                    );
                    return Err(AutomapError::IPv6Unsupported(ip));
                }
            },
        };
        match gateway.add_port(
            PortMappingProtocol::TCP,
            hole_port,
            SocketAddrV4::new(local_ip, hole_port),
            lifetime,
            "",
        ) {
            Ok(_) => Ok(lifetime / 2),
            Err(e)
                if (&format!("{:?}", e) == "OnlyPermanentLeasesSupported")
                    || (&format!("{:?}", e)
                        == "RequestError(ErrorCode(402, \"Invalid Args\"))") =>
            {
                info!(self.logger, "Router accepts only permanent mappings");
                Err(AutomapError::PermanentLeasesOnly)
            }
            Err(e) => {
                warning!(
                    self.logger,
                    "Failed to add {}sec mapping for port {}: \"{:?}\"",
                    lifetime,
                    hole_port,
                    e
                );
                Err(AutomapError::PermanentMappingError(format!("{:?}", e)))
            }
        }
    }
}

impl MappingAdderReal {
    fn new() -> Self {
        Self {
            local_ip_finder: Box::new(LocalIpFinderReal::new()),
            logger: Logger::new("IgdpTransactor"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::tests::LocalIpFinderMock;
    use crate::control_layer::automap_control::AutomapChange;
    use core::ptr::addr_of;
    use crossbeam_channel::unbounded;
    use igd::RequestError;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::AutomapProtocol;
    use std::cell::RefCell;
    use std::net::Ipv6Addr;
    use std::ops::Sub;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    fn clone_get_external_ip_error(error: &GetExternalIpError) -> GetExternalIpError {
        match error {
            GetExternalIpError::ActionNotAuthorized => GetExternalIpError::ActionNotAuthorized,
            GetExternalIpError::RequestError(_) => GetExternalIpError::RequestError(
                RequestError::InvalidResponse("...overflow...".to_string()),
            ),
        }
    }

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

        // This may be called many times quickly in a background thread for testing; therefore,
        // make it so it can never run out of results.
        fn get_external_ip(&self) -> Result<Ipv4Addr, GetExternalIpError> {
            let mut results = self.get_external_ip_results.borrow_mut();
            if results.len() > 1 {
                results.remove(0)
            } else {
                match &results[0] {
                    Ok(ip) => Ok(*ip),
                    Err(e) => Err(clone_get_external_ip_error(e)),
                }
            }
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

    struct MappingAdderMock {
        add_mapping_params: Arc<Mutex<Vec<(*const (), u16, u32)>>>,
        add_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
    }

    // Needed because the mock contains a raw pointer; but we never follow the pointer, we just
    // compare its value.
    unsafe impl Send for MappingAdderMock {}

    impl MappingAdder for MappingAdderMock {
        fn add_mapping(
            &self,
            gateway: &dyn GatewayWrapper,
            hole_port: u16,
            lifetime: u32,
        ) -> Result<u32, AutomapError> {
            self.add_mapping_params.lock().unwrap().push((
                addr_of!(*gateway) as *const (),
                hole_port,
                lifetime,
            ));
            self.add_mapping_results.borrow_mut().remove(0)
        }
    }

    impl MappingAdderMock {
        fn new() -> Self {
            Self {
                add_mapping_params: Arc::new(Mutex::new(vec![])),
                add_mapping_results: RefCell::new(vec![]),
            }
        }

        fn add_mapping_params(mut self, params: &Arc<Mutex<Vec<(*const (), u16, u32)>>>) -> Self {
            self.add_mapping_params = params.clone();
            self
        }

        fn add_mapping_result(self, result: Result<u32, AutomapError>) -> Self {
            self.add_mapping_results.borrow_mut().push(result);
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
        init_test_logging();
        let gateway_factory =
            GatewayFactoryMock::new().make_result(Err(SearchError::InvalidResponse));
        let mut subject = IgdpTransactor::new();
        {
            subject.inner_arc.lock().unwrap().logger = Logger::new("find_routers_handles_error");
        }
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.find_routers();

        assert_eq!(result, Err(AutomapError::CantFindDefaultGateway));
        TestLogHandler::new ().exists_log_containing("WARN: find_routers_handles_error: Error locating routers on the LAN: \"InvalidResponse\"");
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
        assert_eq!(
            subject.inner_arc.lock().unwrap().public_ip_opt,
            Some(public_ipv4)
        );
    }

    #[test]
    fn get_public_ip_handles_error() {
        init_test_logging();
        let gateway = GatewayWrapperMock::new()
            .get_external_ip_result(Err(GetExternalIpError::ActionNotAuthorized));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.get_public_ip(IpAddr::from_str("192.168.0.255").unwrap());

        assert_eq!(
            result,
            Err(AutomapError::GetPublicIpError(
                "ActionNotAuthorized".to_string()
            ))
        );
        assert_eq!(subject.inner_arc.lock().unwrap().public_ip_opt, None);
        TestLogHandler::new()
            .exists_log_containing("WARN: IgdpTransactor: Error getting public IP from router at 192.168.0.255: \"ActionNotAuthorized\"");
    }

    #[test]
    fn add_mapping_works() {
        let local_ip = LocalIpFinderReal::new().find().unwrap();
        let local_ipv4 = match local_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                eprintln!("This test can't run on machines with no IPv4 IP address");
                return;
            }
        };
        let add_port_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = GatewayWrapperMock::new()
            .add_port_params(&add_port_params_arc)
            .add_port_result(Ok(()));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject
            .add_mapping(IpAddr::from_str("192.168.0.1").unwrap(), 7777, 1234)
            .unwrap();

        assert_eq!(result, 617);
        let inner = subject.inner_arc.lock().unwrap();
        assert_eq!(
            inner.change_handler_config_opt.take(),
            Some(HousekeeperConfig {
                hole_port: 7777,
                next_lifetime: Duration::from_secs(1234),
                remap_interval: Duration::from_secs(617),
            })
        );
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
        let local_ip = LocalIpFinderReal::new().find().unwrap();
        let local_ipv4 = match local_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                eprintln!("This test can't run on machines with no IPv4 IP address");
                return;
            }
        };
        let add_port_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = GatewayWrapperMock::new()
            .add_port_params(&add_port_params_arc)
            .add_port_result(Ok(()));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

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
    fn mapping_adder_works() {
        let local_ipv4 = Ipv4Addr::from_str("192.168.0.101").unwrap();
        let local_ip = IpAddr::V4(local_ipv4);
        let add_port_params_arc = Arc::new(Mutex::new(vec![]));
        let gateway = GatewayWrapperMock::new()
            .add_port_params(&add_port_params_arc)
            .add_port_result(Ok(()));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = MappingAdderReal::new();
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(&gateway, 7777, 1234).unwrap();

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
    fn add_mapping_complains_about_not_being_able_to_find_local_ip() {
        init_test_logging();
        let gateway = GatewayWrapperMock::new();
        let local_ip_finder = LocalIpFinderMock::new()
            .find_result(Err(AutomapError::GetPublicIpError("Booga".to_string())));
        let mut subject = MappingAdderReal::new();
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(&gateway, 777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::GetPublicIpError("Booga".to_string()))
        );
        TestLogHandler::new().exists_log_containing("WARN: IgdpTransactor: Cannot determine local IP address: \"GetPublicIpError(\"Booga\")\"");
    }

    #[test]
    fn add_mapping_complains_about_ipv6_local_address() {
        init_test_logging();
        let local_ipv6 = Ipv6Addr::from_str("0000:1111:2222:3333:4444:5555:6666:7777").unwrap();
        let gateway = GatewayWrapperMock::new().add_port_result(Ok(()));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(IpAddr::V6(local_ipv6)));
        let mut subject = MappingAdderReal::new();
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(&gateway, 7777, 1234);

        assert_eq!(result, Err(AutomapError::IPv6Unsupported(local_ipv6)));
        TestLogHandler::new().exists_log_containing(
            "WARN: IgdpTransactor: IGDP is incompatible with an IPv6 local IP address",
        );
    }

    #[test]
    fn add_mapping_handles_only_permanent_lease_error() {
        init_test_logging();
        let local_ip = IpAddr::from_str("192.168.0.101").unwrap();
        let gateway = GatewayWrapperMock::new()
            .add_port_result(Err(AddPortError::OnlyPermanentLeasesSupported));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = MappingAdderReal::new();
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(&gateway, 7777, 1234);

        assert_eq!(result, Err(AutomapError::PermanentLeasesOnly));
        TestLogHandler::new()
            .exists_log_containing("INFO: IgdpTransactor: Router accepts only permanent mappings");
    }

    #[test]
    fn add_mapping_handles_invalid_args_error_indicating_permanent_leases_only() {
        let local_ip = IpAddr::from_str("192.168.0.101").unwrap();
        let gateway = GatewayWrapperMock::new().add_port_result(Err(AddPortError::RequestError(
            RequestError::ErrorCode(402, "Invalid Args".to_string()),
        )));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = MappingAdderReal::new();
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(&gateway, 7777, 1234);

        assert_eq!(result, Err(AutomapError::PermanentLeasesOnly));
    }

    #[test]
    fn add_mapping_handles_other_error() {
        init_test_logging();
        let local_ip = IpAddr::from_str("192.168.0.253").unwrap();
        let gateway = GatewayWrapperMock::new().add_port_result(Err(AddPortError::PortInUse));
        let local_ip_finder = LocalIpFinderMock::new().find_result(Ok(local_ip));
        let mut subject = MappingAdderReal::new();
        subject.local_ip_finder = Box::new(local_ip_finder);

        let result = subject.add_mapping(&gateway, 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError("PortInUse".to_string()))
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: IgdpTransactor: Failed to add 1234sec mapping for port 7777: \"PortInUse\"",
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
        init_test_logging();
        let gateway =
            GatewayWrapperMock::new().remove_port_result(Err(RemovePortError::NoSuchPortMapping));
        let gateway_factory = GatewayFactoryMock::new().make_result(Ok(gateway));
        let mut subject = IgdpTransactor::new();
        subject.gateway_factory = Box::new(gateway_factory);

        let result = subject.delete_mapping(IpAddr::from_str("192.168.0.254").unwrap(), 7777);

        assert_eq!(
            result,
            Err(AutomapError::DeleteMappingError(
                "NoSuchPortMapping".to_string()
            ))
        );
        TestLogHandler::new ()
            .exists_log_containing("WARN: IgdpTransactor: Can't delete mapping of port 7777 through router at 192.168.0.254: \"NoSuchPortMapping\"");
    }

    #[test]
    fn start_change_handler_complains_if_change_handler_is_already_running() {
        init_test_logging();
        let mut subject = IgdpTransactor::new();
        subject.inner_arc.lock().unwrap().housekeeping_commander_opt = Some(unbounded().0);

        let result = subject.start_housekeeping_thread(
            Box::new(|_| ()),
            IpAddr::from_str("192.168.0.254").unwrap(),
        );

        assert_eq!(
            result.err().unwrap(),
            AutomapError::ChangeHandlerAlreadyRunning
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: IgdpTransactor: Change handler for router at 192.168.0.254 is already running",
        );
    }

    #[test]
    fn start_change_handler_notices_address_changes() {
        let one_ip = Ipv4Addr::from_str("1.2.3.4").unwrap();
        let another_ip = Ipv4Addr::from_str("4.3.2.1").unwrap();
        let router_ip = IpAddr::from_str("5.5.5.5").unwrap();
        let mut subject = IgdpTransactor::new();
        {
            let mut inner = subject.inner_arc.lock().unwrap();
            inner.gateway_opt = Some(Box::new(
                GatewayWrapperMock::new()
                    .get_external_ip_result(Ok(one_ip))
                    .get_external_ip_result(Ok(one_ip))
                    .get_external_ip_result(Ok(one_ip))
                    .get_external_ip_result(Ok(another_ip))
                    .get_external_ip_result(Ok(another_ip))
                    .get_external_ip_result(Ok(one_ip))
                    .get_external_ip_result(Ok(another_ip)),
            ));
            inner.public_ip_opt = Some(one_ip);
        }
        subject.public_ip_poll_delay_ms = 10;
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_arc = change_log_arc.clone();
        let change_handler =
            Box::new(move |change: AutomapChange| inner_arc.lock().unwrap().push(change));

        subject
            .start_housekeeping_thread(change_handler, router_ip)
            .unwrap();

        thread::sleep(Duration::from_millis(100));
        let _ = subject.stop_housekeeping_thread();
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(
            *change_log,
            vec![
                AutomapChange::NewIp(IpAddr::V4(another_ip)),
                AutomapChange::NewIp(IpAddr::V4(one_ip)),
                AutomapChange::NewIp(IpAddr::V4(another_ip)),
            ]
        );
        let inner = subject.inner_arc.lock().unwrap();
        assert_eq!(inner.public_ip_opt, Some(another_ip));
    }

    #[test]
    fn start_change_handler_handles_absence_of_gateway() {
        init_test_logging();
        let public_ip = Ipv4Addr::from_str("1.2.3.4").unwrap();
        let router_ip = IpAddr::from_str("192.168.0.255").unwrap();
        let mut subject = IgdpTransactor::new();
        subject.public_ip_poll_delay_ms = 10;
        {
            let mut inner = subject.inner_arc.lock().unwrap();
            inner.gateway_opt = None;
            inner.public_ip_opt = Some(public_ip);
        }
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_arc = change_log_arc.clone();
        let change_handler =
            Box::new(move |change: AutomapChange| inner_arc.lock().unwrap().push(change));

        subject
            .start_housekeeping_thread(change_handler, router_ip)
            .unwrap();

        thread::sleep(Duration::from_millis(100));
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(
            *change_log,
            vec![AutomapChange::Error(AutomapError::CantFindDefaultGateway)]
        );
        let inner = subject.inner_arc.lock().unwrap();
        assert_eq!(inner.public_ip_opt, Some(public_ip));
        assert!(inner.housekeeping_commander_opt.is_none());
        TestLogHandler::new().exists_log_containing("ERROR: IgdpTransactor: Can't find router");
    }

    #[test]
    fn stop_housekeeping_thread_returns_same_change_handler_sent_into_start_housekeeping_thread() {
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_cla = change_log_arc.clone();
        let change_handler = Box::new(move |change| {
            let mut change_log = inner_cla.lock().unwrap();
            change_log.push(change)
        });
        let mut subject = IgdpTransactor::new();
        subject.public_ip_poll_delay_ms = 10;
        let _ =
            subject.start_housekeeping_thread(change_handler, IpAddr::from_str("1.2.3.4").unwrap());

        let change_handler = subject.stop_housekeeping_thread();

        let change = AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap());
        change_handler(change.clone());
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(change_log.last().unwrap(), &change)
    }

    #[test]
    #[should_panic(expected = "No HousekeepingCommander: can't stop housekeeping thread")]
    fn stop_housekeeping_thread_handles_missing_housekeeper_commander() {
        let mut subject = IgdpTransactor::new();
        subject.inner_arc.lock().unwrap().housekeeping_commander_opt = None;

        let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn stop_housekeeping_thread_handles_broken_commander_connection() {
        init_test_logging();
        let mut subject = IgdpTransactor::new();
        let (tx, rx) = unbounded();
        subject.inner_arc.lock().unwrap().housekeeping_commander_opt = Some(tx);
        std::mem::drop(rx);

        let change_handler = subject.stop_housekeeping_thread();

        change_handler(AutomapChange::Error(
            AutomapError::HousekeeperUnconfigured,
        ));
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("WARN: IgdpTransactor: Tried to stop housekeeping thread that had already disconnected from the commander");
        tlh.exists_log_containing("ERROR: IgdpTransactor: Change handler recovery failed: discarded Error(ChangeHandlerUnconfigured)");
    }

    #[test]
    #[should_panic(expected = "No JoinHandle: can't stop housekeeping thread")]
    fn stop_housekeeping_thread_handles_missing_join_handle() {
        let mut subject = IgdpTransactor::new();
        let (tx, _rx) = unbounded();
        subject.inner_arc.lock().unwrap().housekeeping_commander_opt = Some(tx);
        subject.join_handle_opt = None;

        let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn stop_housekeeping_thread_handles_panicked_housekeeping_thread() {
        init_test_logging();
        let mut subject = IgdpTransactor::new();
        let (tx, _rx) = unbounded();
        subject.inner_arc.lock().unwrap().housekeeping_commander_opt = Some(tx);
        subject.join_handle_opt = Some(thread::spawn(|| panic!("Booga!")));

        let change_handler = subject.stop_housekeeping_thread();

        change_handler(AutomapChange::Error(AutomapError::CantFindDefaultGateway));
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            "WARN: IgdpTransactor: Tried to stop housekeeping thread that had panicked",
        );
        tlh.exists_log_containing("ERROR: IgdpTransactor: Change handler recovery failed: discarded Error(CantFindDefaultGateway)");
    }

    #[test]
    fn thread_guts_does_not_remap_if_interval_does_not_run_out() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let gateway = GatewayWrapperMock::new()
            .get_external_ip_result(Ok(Ipv4Addr::from_str("1.2.3.4").unwrap()));
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: Some(Box::new(gateway)),
            housekeeping_commander_opt: None,
            public_ip_opt: None,
            mapping_adder: Box::new(MappingAdderMock::new()),
            change_handler_config_opt: RefCell::new(None),
            logger: Logger::new("no_remap_test"),
        }));
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(1000))
            .unwrap();
        tx.send(HousekeepingThreadCommand::Stop).unwrap();

        let _ = IgdpTransactor::thread_guts(10, change_handler, inner_arc, rx);

        TestLogHandler::new().exists_no_log_containing("INFO: no_remap_test: Remapping port 1234");
    }

    #[test]
    fn thread_guts_remaps_when_interval_runs_out() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder = Box::new(
            MappingAdderMock::new()
                .add_mapping_params(&add_mapping_params_arc)
                .add_mapping_result(Ok(300)),
        );
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let gateway = GatewayWrapperMock::new()
            .get_external_ip_result(Ok(Ipv4Addr::from_str("192.168.0.1").unwrap()));
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: Some(Box::new(gateway)),
            housekeeping_commander_opt: None,
            public_ip_opt: None,
            mapping_adder,
            change_handler_config_opt: RefCell::new(Some(HousekeeperConfig {
                hole_port: 6689,
                next_lifetime: Duration::from_secs(10),
                remap_interval: Duration::from_secs(0),
            })),
            logger: Logger::new("timed_remap_test"),
        }));
        let inner_arc_inner = inner_arc.clone();
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(80))
            .unwrap();

        let handle = thread::spawn(move || {
            IgdpTransactor::thread_guts(10, change_handler, inner_arc_inner, rx)
        });

        thread::sleep(Duration::from_millis(100));
        tx.send(HousekeepingThreadCommand::Stop).unwrap();
        let _ = handle.join().unwrap();
        let inner = inner_arc.lock().unwrap();
        assert_eq!(
            inner.change_handler_config_opt.take(),
            Some(HousekeeperConfig {
                hole_port: 6689,
                next_lifetime: Duration::from_secs(10),
                remap_interval: Duration::from_secs(0),
            })
        );
        let (_, hole_port, lifetime) = add_mapping_params_arc.lock().unwrap().remove(0);
        assert_eq!(hole_port, 6689);
        assert_eq!(lifetime, 1);
        TestLogHandler::new().exists_log_containing("INFO: timed_remap_test: Remapping port 6689");
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

    #[test]
    fn thread_guts_iteration_handles_missing_public_ip() {
        init_test_logging();
        let new_public_ip = Ipv4Addr::from_str("4.3.2.1").unwrap();
        let gateway = GatewayWrapperMock::new().get_external_ip_result(Ok(new_public_ip));
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: Some(Box::new(gateway)),
            housekeeping_commander_opt: None,
            public_ip_opt: None,
            mapping_adder: Box::new(MappingAdderMock::new()),
            change_handler_config_opt: RefCell::new(None),
            logger: Logger::new("test"),
        }));
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let change_log_inner = change_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_log_inner.lock().unwrap().push(change));

        let result = IgdpTransactor::thread_guts_iteration(
            &change_handler,
            &inner_arc,
            &mut Instant::now(),
            Duration::from_millis(1000),
        );

        assert!(result);
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(
            *change_log,
            vec![AutomapChange::NewIp(IpAddr::V4(new_public_ip))]
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: test: Change handler was started before retrieving public IP",
        );
    }

    #[test]
    fn thread_guts_iteration_handles_missing_change_handler_config() {
        let new_public_ip = Ipv4Addr::from_str("4.3.2.1").unwrap();
        let gateway = GatewayWrapperMock::new().get_external_ip_result(Ok(new_public_ip));
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: Some(Box::new(gateway)),
            housekeeping_commander_opt: None,
            public_ip_opt: Some(new_public_ip),
            mapping_adder: Box::new(MappingAdderMock::new()),
            change_handler_config_opt: RefCell::new(None),
            logger: Logger::new("thread_guts_iteration_handles_missing_change_handler_config"),
        }));
        let change_handler: ChangeHandler = Box::new(move |_| panic!("Shouldn't be called"));

        let result = IgdpTransactor::thread_guts_iteration(
            &change_handler,
            &inner_arc,
            &mut Instant::now().sub(Duration::from_secs(1)),
            Duration::from_millis(0),
        );

        assert!(result);
    }

    #[test]
    fn thread_guts_iteration_handles_remap_error() {
        init_test_logging();
        let new_public_ip = Ipv4Addr::from_str("4.3.2.1").unwrap();
        let gateway = GatewayWrapperMock::new().get_external_ip_result(Ok(new_public_ip));
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: Some(Box::new(gateway)),
            housekeeping_commander_opt: None,
            public_ip_opt: Some(new_public_ip),
            mapping_adder: Box::new(MappingAdderMock::new().add_mapping_result(Err(
                AutomapError::PermanentMappingError("Booga".to_string()),
            ))),
            change_handler_config_opt: RefCell::new(Some(HousekeeperConfig {
                hole_port: 6689,
                next_lifetime: Duration::from_secs(600),
                remap_interval: Duration::from_secs(0),
            })),
            logger: Logger::new("test"),
        }));
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let change_log_inner = change_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_log_inner.lock().unwrap().push(change));

        let result = IgdpTransactor::thread_guts_iteration(
            &change_handler,
            &inner_arc,
            &mut Instant::now().sub(Duration::from_secs(1)),
            Duration::from_millis(0),
        );

        assert!(result);
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(
            *change_log,
            vec![AutomapChange::Error(AutomapError::PermanentMappingError(
                "Booga".to_string()
            ))]
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: test: Remapping failure: PermanentMappingError(\"Booga\")",
        );
    }

    #[test]
    fn thread_guts_iteration_reports_router_error_to_change_handler() {
        init_test_logging();
        let gateway = GatewayWrapperMock::new()
            .get_external_ip_result(Err(GetExternalIpError::ActionNotAuthorized));
        let inner_arc = Arc::new(Mutex::new(IgdpTransactorInner {
            gateway_opt: Some(Box::new(gateway)),
            housekeeping_commander_opt: None,
            public_ip_opt: Some(Ipv4Addr::from_str("1.2.3.4").unwrap()),
            mapping_adder: Box::new(MappingAdderMock::new()),
            change_handler_config_opt: RefCell::new(None),
            logger: Logger::new("test"),
        }));
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let change_log_inner = change_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_log_inner.lock().unwrap().push(change));

        let result = IgdpTransactor::thread_guts_iteration(
            &change_handler,
            &inner_arc,
            &mut Instant::now(),
            Duration::from_millis(0),
        );

        assert!(result);
        let change_log = change_log_arc.lock().unwrap();
        let err_msg = "ActionNotAuthorized";
        assert_eq!(
            *change_log,
            vec![AutomapChange::Error(AutomapError::GetPublicIpError(
                err_msg.to_string()
            ))]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: test: Change handler could not get public IP from router: {}",
            err_msg
        ));
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_greater_than_one_second() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder = MappingAdderMock::new()
            .add_mapping_params(&add_mapping_params_arc)
            .add_mapping_result(Err(AutomapError::Unknown));
        let gateway = GatewayWrapperMock::new();
        let expected_gateway_ptr = addr_of!(gateway) as *const ();

        let result = IgdpTransactor::remap_port(
            &mapping_adder,
            &gateway,
            6689,
            Duration::from_millis(100900),
            &Logger::new("test"),
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut add_mapping_params = add_mapping_params_arc.lock().unwrap();
        let (actual_gateway_ptr, hole_port, requested_lifetime) = add_mapping_params.remove(0);
        assert_eq!(actual_gateway_ptr, expected_gateway_ptr);
        assert_eq!(hole_port, 6689);
        assert_eq!(requested_lifetime, 100);
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_less_than_one_second() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder = MappingAdderMock::new()
            .add_mapping_params(&add_mapping_params_arc)
            .add_mapping_result(Err(AutomapError::Unknown));
        let gateway = GatewayWrapperMock::new();
        let expected_gateway_ptr = addr_of!(gateway) as *const ();

        let result = IgdpTransactor::remap_port(
            &mapping_adder,
            &gateway,
            6689,
            Duration::from_millis(80),
            &Logger::new("test"),
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut add_mapping_params = add_mapping_params_arc.lock().unwrap();
        let (actual_gateway_ptr, hole_port, requested_lifetime) = add_mapping_params.remove(0);
        assert_eq!(actual_gateway_ptr, expected_gateway_ptr);
        assert_eq!(hole_port, 6689);
        assert_eq!(requested_lifetime, 1);
    }

    #[test]
    fn remap_port_handles_mapping_failure() {
        let mapping_adder = MappingAdderMock::new().add_mapping_result(Err(
            AutomapError::PermanentMappingError("Booga".to_string()),
        ));
        let gateway = GatewayWrapperMock::new();

        let result = IgdpTransactor::remap_port(
            &mapping_adder,
            &gateway,
            0,
            Duration::from_millis(80),
            &Logger::new("test"),
        );

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError("Booga".to_string()))
        );
    }
}
