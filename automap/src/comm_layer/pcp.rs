// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{find_routers, make_local_socket_address, FreePortFactory, FreePortFactoryReal, MappingConfig, UdpSocketWrapperFactoryReal, UdpSocketWrapper, UdpSocketWrapperFactory, ANNOUNCEMENT_MULTICAST_GROUP, ANNOUNCEMENT_READ_TIMEOUT_MILLIS, ROUTER_PORT, ANNOUNCEMENT_PORT};
use crate::comm_layer::{
    AutomapError, AutomapErrorCause, HousekeepingThreadCommand, LocalIpFinder, LocalIpFinderReal,
    Transactor,
};
use crate::control_layer::automap_control::{AutomapChange, ChangeHandler};
use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
use crate::protocols::pcp::pcp_packet::{Opcode, PcpPacket, ResultCode};
use crate::protocols::utils::{Direction, Packet};
use crossbeam_channel::{unbounded, Receiver, Sender};
use masq_lib::error;
use masq_lib::info;
use masq_lib::logger::Logger;
use masq_lib::utils::AutomapProtocol;
use masq_lib::{debug, warning};
use pretty_hex::PrettyHex;
use rand::RngCore;
use std::any::Any;
use std::convert::TryFrom;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{io, thread};

trait MappingNonceFactory: Send {
    fn make(&self) -> [u8; 12];
}

struct MappingNonceFactoryReal {}

impl MappingNonceFactory for MappingNonceFactoryReal {
    fn make(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}

impl MappingNonceFactoryReal {
    fn new() -> Self {
        Self {}
    }
}

struct Factories {
    socket_factory: Box<dyn UdpSocketWrapperFactory>,
    local_ip_finder: Box<dyn LocalIpFinder>,
    mapping_nonce_factory: Box<dyn MappingNonceFactory>,
    free_port_factory: Box<dyn FreePortFactory>,
}

impl Default for Factories {
    fn default() -> Self {
        Self {
            socket_factory: Box::new(UdpSocketWrapperFactoryReal::new()),
            local_ip_finder: Box::new(LocalIpFinderReal::new()),
            mapping_nonce_factory: Box::new(MappingNonceFactoryReal::new()),
            free_port_factory: Box::new(FreePortFactoryReal::new()),
        }
    }
}

struct PcpTransactorInner {
    mapping_transactor: Box<dyn MappingTransactor>,
    factories: Factories,
}

pub struct PcpTransactor {
    inner_arc: Arc<Mutex<PcpTransactorInner>>,
    router_port: u16,
    announcement_multicast_group: u8,
    announcement_port: u16,
    housekeeper_commander_opt: Option<Sender<HousekeepingThreadCommand>>,
    join_handle_opt: Option<JoinHandle<ChangeHandler>>,
    read_timeout_millis: u64,
    logger: Logger,
}

impl Transactor for PcpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        debug!(self.logger, "Seeking routers on LAN");
        find_routers()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        debug!(
            self.logger,
            "Seeking public IP from router at {}", router_ip
        );
        let inner = self.inner();
        Ok(inner
            .mapping_transactor
            .transact(
                &inner.factories,
                SocketAddr::new(router_ip, self.router_port),
                &mut MappingConfig {
                    // We have to have something here. Its value doesn't really matter, as long as
                    // it's not a port somebody else has mapped so that we don't accidentally
                    // delete (lifetime is zero) their mapping. Documentation suggests 9.
                    hole_port: 9,
                    next_lifetime: Duration::from_secs(0),
                    remap_interval: Duration::from_secs(0),
                },
            )?
            .1
            .external_ip_address)
    }

    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        debug!(
            self.logger,
            "Adding mapping for port {} through router at {} for {} seconds",
            hole_port,
            router_ip,
            lifetime
        );
        let inner = self.inner();
        let mut mapping_config = MappingConfig {
            hole_port,
            next_lifetime: Duration::from_secs(lifetime as u64),
            remap_interval: Duration::from_secs(0),
        };
        let approved_lifetime = inner
            .mapping_transactor
            .transact(
                &inner.factories,
                SocketAddr::new(router_ip, self.router_port),
                &mut mapping_config,
            )?
            .0;
        self.housekeeper_commander_opt
            .as_ref()
            .expect("Start housekeeping thread before adding a mapping")
            .try_send(HousekeepingThreadCommand::InitializeMappingConfig(
                mapping_config,
            ))
            .expect("Housekeepig thread panicked");
        Ok(approved_lifetime / 2)
    }

    fn add_permanent_mapping(
        &self,
        _router_ip: IpAddr,
        _hole_port: u16,
    ) -> Result<u32, AutomapError> {
        panic!("PCP cannot add permanent mappings")
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        debug!(
            self.logger,
            "Deleting mapping of port {} through router at {}", hole_port, router_ip
        );
        let inner = self.inner();
        inner
            .mapping_transactor
            .transact(
                &inner.factories,
                SocketAddr::new(router_ip, self.router_port),
                &mut MappingConfig {
                    hole_port,
                    next_lifetime: Duration::from_secs(0),
                    remap_interval: Duration::from_secs(0),
                },
            )
            .map(|_| ())
    }

    fn protocol(&self) -> AutomapProtocol {
        AutomapProtocol::Pcp
    }

    fn start_housekeeping_thread(
        &mut self,
        change_handler: ChangeHandler,
        router_ip: IpAddr,
    ) -> Result<Sender<HousekeepingThreadCommand>, AutomapError> {
        debug!(
            self.logger,
            "Starting housekeeping thread for router at {}", router_ip
        );
        if let Some(_change_handler_stopper) = &self.housekeeper_commander_opt {
            return Err(AutomapError::HousekeeperAlreadyRunning);
        }
        let socket = self.make_announcement_socket()?;
        let (tx, rx) = unbounded();
        self.housekeeper_commander_opt = Some(tx.clone());
        let inner_arc = self.inner_arc.clone();
        let router_addr = SocketAddr::new(router_ip, self.router_port);
        let read_timeout_millis = self.read_timeout_millis;
        let logger = self.logger.clone();
        self.join_handle_opt = Some(thread::spawn(move || {
            Self::thread_guts(
                socket.as_ref(),
                &rx,
                inner_arc,
                router_addr,
                change_handler,
                read_timeout_millis,
                logger,
            )
        }));
        Ok(tx)
    }

    fn stop_housekeeping_thread(&mut self) -> Result<ChangeHandler, AutomapError> {
        debug!(self.logger, "Stopping housekeeping thread");
        let stopper = self
            .housekeeper_commander_opt
            .take()
            .expect("No HousekeepingCommander: can't stop housekeeping thread");
        let change_handler = match stopper.send(HousekeepingThreadCommand::Stop) {
            Ok(_) => {
                let join_handle = self
                    .join_handle_opt
                    .take()
                    .expect("No JoinHandle: can't stop housekeeping thread");
                match join_handle.join() {
                    Ok(change_handler) => change_handler,
                    Err(_) => {
                        warning!(
                            self.logger,
                            "Tried to stop housekeeping thread that had panicked"
                        );
                        return Err(AutomapError::HousekeeperCrashed);
                    }
                }
            }
            Err(_) => {
                warning!(self.logger, "Tried to stop housekeeping thread that had already disconnected from the commander");
                return Err(AutomapError::HousekeeperCrashed);
            }
        };
        Ok(change_handler)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for PcpTransactor {
    fn default() -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(PcpTransactorInner {
                mapping_transactor: Box::<MappingTransactorReal>::default(),
                factories: Factories::default(),
            })),
            router_port: ROUTER_PORT,
            announcement_multicast_group: ANNOUNCEMENT_MULTICAST_GROUP,
            announcement_port: ANNOUNCEMENT_PORT,
            housekeeper_commander_opt: None,
            join_handle_opt: None,
            read_timeout_millis: ANNOUNCEMENT_READ_TIMEOUT_MILLIS,
            logger: Logger::new("PcpTransactor"),
        }
    }
}

impl PcpTransactor {
    fn inner(&self) -> MutexGuard<PcpTransactorInner> {
        self.inner_arc
            .lock()
            .expect("PCP Housekeeping Thread is dead")
    }

    fn make_announcement_socket(&mut self) -> Result<Box<dyn UdpSocketWrapper>, AutomapError> {
        let socket_result = {
            let factories = &self.inner().factories;
            factories.socket_factory.make_multicast(
                self.announcement_multicast_group,
                self.announcement_port,
            )
        };
        let socket = match socket_result {
            Ok(s) => s,
            Err(e) => {
                let multicast = Ipv4Addr::new(224, 0, 0, self.announcement_multicast_group);
                return Err(AutomapError::SocketBindingError(
                    format!("{:?}", e),
                    SocketAddr::new(IpAddr::V4(multicast), self.announcement_port),
                ));
            }
        };
        Ok(socket)
    }

    #[allow(clippy::too_many_arguments)]
    fn thread_guts(
        announcement_socket: &dyn UdpSocketWrapper,
        rx: &Receiver<HousekeepingThreadCommand>,
        inner_arc: Arc<Mutex<PcpTransactorInner>>,
        router_addr: SocketAddr,
        change_handler: ChangeHandler,
        read_timeout_millis: u64,
        logger: Logger,
    ) -> ChangeHandler {
        let mut last_remapped = Instant::now();
        let mut mapping_config_opt: Option<MappingConfig> = None;
        let mut buffer = [0u8; 100];
        announcement_socket
            .set_read_timeout(Some(Duration::from_millis(read_timeout_millis)))
            .expect("Can't set read timeout");
        loop {
            match rx.try_recv() {
                Ok(HousekeepingThreadCommand::Stop) => {
                    break;
                }
                Ok(HousekeepingThreadCommand::SetRemapIntervalMs(remap_after)) => {
                    match &mut mapping_config_opt {
                        None => {
                            error!(
                                logger,
                                "Can't set remap interval until after first mapping request"
                            );
                        }
                        Some(mapping_config) => {
                            debug!(
                                logger,
                                "Changing remap interval from {}ms to {}ms",
                                mapping_config.remap_interval.as_millis(),
                                remap_after
                            );
                            mapping_config.remap_interval = Duration::from_millis(remap_after)
                        }
                    }
                }
                Ok(HousekeepingThreadCommand::InitializeMappingConfig(mapping_config)) => {
                    mapping_config_opt.replace(mapping_config);
                }
                Err(_) => (),
            }
            // This will block for read_timeout_millis, conserving CPU cycles
            match announcement_socket.recv_from(&mut buffer) {
                Ok((len, sender_address)) => {
                    if sender_address.ip() != router_addr.ip() {
                        continue;
                    }
                    match PcpPacket::try_from(&buffer[0..len]) {
                        Ok(packet) => {
                            if packet.opcode == Opcode::Announce {
                                debug!(logger, "Received IP-change announcement");
                                let inner = inner_arc.lock().expect("PcpTransactor is dead");
                                Self::handle_announcement(
                                    &inner,
                                    router_addr,
                                    &change_handler,
                                    &mut mapping_config_opt,
                                    &logger,
                                );
                            }
                        }
                        Err(_) => error!(
                            logger,
                            "Unparseable PCP packet:\n{}",
                            PrettyHex::hex_dump(&&buffer[0..len])
                        ),
                    }
                }
                #[allow(clippy::unused_unit)] // Clippy and the formatter argue over this one
                Err(e)
                    if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) =>
                {
                    ()
                }
                Err(e) => error!(logger, "Error receiving PCP packet from router: {:?}", e),
            }
            let since_last_remapped = last_remapped.elapsed();
            match &mut mapping_config_opt {
                None => (),
                Some(mapping_config) => {
                    if since_last_remapped.gt(&mapping_config.remap_interval) {
                        let inner = inner_arc.lock().expect("PcpTransactor is dead");
                        let requested_lifetime = mapping_config.next_lifetime;
                        if let Err(e) = Self::remap_port(
                            &inner,
                            router_addr,
                            mapping_config,
                            requested_lifetime,
                            &logger,
                        ) {
                            error!(logger, "Remapping failure: {:?}", e);
                            change_handler(AutomapChange::Error(e));
                        }
                        last_remapped = Instant::now();
                    }
                }
            }
        }
        change_handler
    }

    fn remap_port(
        inner: &PcpTransactorInner,
        router_addr: SocketAddr,
        mapping_config: &mut MappingConfig,
        requested_lifetime: Duration,
        logger: &Logger,
    ) -> Result<u32, AutomapError> {
        info!(logger, "Remapping port {}", mapping_config.hole_port);
        let mut requested_lifetime_secs = requested_lifetime.as_secs() as u32;
        if requested_lifetime_secs < 1 {
            requested_lifetime_secs = 1;
        }
        mapping_config.next_lifetime = Duration::from_secs(requested_lifetime_secs as u64);
        Ok(inner
            .mapping_transactor
            .transact(&inner.factories, router_addr, mapping_config)?
            .0)
    }

    fn handle_announcement(
        inner: &PcpTransactorInner,
        router_addr: SocketAddr,
        change_handler: &ChangeHandler,
        mapping_config_opt: &mut Option<MappingConfig>,
        logger: &Logger,
    ) {
        let mut local_mapping_config = MappingConfig {
            hole_port: 9, // meaningless port suggested in PCP RFC document
            next_lifetime: Duration::from_secs(0),
            remap_interval: Duration::from_secs(0),
        };
        let mapping_config = match mapping_config_opt.as_mut() {
            Some(mc) => mc,
            None => &mut local_mapping_config,
        };
        match inner
            .mapping_transactor
            .transact(&inner.factories, router_addr, mapping_config)
        {
            Ok((_, opcode_data)) => {
                debug!(
                    logger,
                    "Received announcement that public IP address changed to {}",
                    opcode_data.external_ip_address
                );
                change_handler(AutomapChange::NewIp(opcode_data.external_ip_address))
            }
            Err(e) => {
                error!(
                    logger,
                    "Remapping after IP change failed, Node is useless: {:?}", e
                );
                change_handler(AutomapChange::Error(e))
            }
        }
    }
}

trait MappingTransactor: Send {
    fn transact(
        &self,
        factories: &Factories,
        router_addr: SocketAddr,
        mapping_config: &mut MappingConfig,
    ) -> Result<(u32, MapOpcodeData), AutomapError>;
}

struct MappingTransactorReal {
    logger: Logger,
}

impl MappingTransactor for MappingTransactorReal {
    fn transact(
        &self,
        factories: &Factories,
        router_addr: SocketAddr,
        mapping_config: &mut MappingConfig,
    ) -> Result<(u32, MapOpcodeData), AutomapError> {
        debug!(
            self.logger,
            "Mapping transaction: port {} through router at {} for {} seconds",
            mapping_config.hole_port,
            router_addr,
            mapping_config.next_lifetime_secs()
        );
        let (socket_addr, socket_result, local_ip_result, mapping_nonce) =
            Self::employ_factories(factories, router_addr.ip());
        let packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: mapping_config.next_lifetime_secs(),
            client_ip_opt: Some(local_ip_result?),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce,
                protocol: Protocol::Tcp,
                internal_port: mapping_config.hole_port,
                external_port: mapping_config.hole_port,
                external_ip_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            }),
            options: vec![],
        };
        let mut buffer = [0u8; 1100];
        let request_len = packet
            .marshal(&mut buffer)
            .expect("Bad packet construction");
        let socket = match socket_result {
            Ok(s) => s,
            Err(e) => {
                warning!(
                    self.logger,
                    "Error while connecting to router at {}: \"{:?}\"",
                    socket_addr,
                    e
                );
                return Err(AutomapError::SocketBindingError(
                    format!("{:?}", e),
                    socket_addr,
                ));
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set_read_timeout failed");
        match socket.send_to(&buffer[0..request_len], router_addr) {
            Ok(_) => (),
            Err(e) => {
                warning!(
                    self.logger,
                    "Error while transmitting to router at {}: \"{:?}\"",
                    router_addr,
                    e
                );
                return Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                    format!("{:?}", e),
                )));
            }
        };
        let response = match socket.recv_from(&mut buffer) {
            Ok((len, _peer_addr)) => match PcpPacket::try_from(&buffer[0..len]) {
                Ok(pkt) => pkt,
                Err(e) => {
                    warning!(
                        self.logger,
                        "Error while parsing packet from router at {}: \"{:?}\"",
                        router_addr,
                        e
                    );
                    return Err(AutomapError::PacketParseError(e));
                }
            },
            Err(e) if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) => {
                return Err(AutomapError::ProtocolError(
                    "Timed out after 3 seconds".to_string(),
                ))
            }
            Err(e) => {
                warning!(
                    self.logger,
                    "Error while receiving from router at {}: \"{:?}\"",
                    router_addr,
                    e
                );
                return Err(AutomapError::SocketReceiveError(
                    AutomapErrorCause::Unknown(format!("{:?}", e)),
                ));
            }
        };
        if response.direction != Direction::Response {
            let e = AutomapError::ProtocolError("Map response labeled as request".to_string());
            warning!(
                self.logger,
                "Router at {} is misbehaving: \"{:?}\"",
                router_addr,
                e
            );
            return Err(e);
        }
        if response.opcode != Opcode::Map {
            let e = AutomapError::ProtocolError(format!(
                "Map response has opcode {:?} instead of Map",
                response.opcode
            ));
            warning!(
                self.logger,
                "Router at {} is misbehaving: \"{:?}\"",
                router_addr,
                e
            );
            return Err(e);
        }
        Self::compute_mapping_result(response, router_addr, &self.logger).map(
            |(approved_lifetime, opcode_data)| {
                mapping_config.next_lifetime = Duration::from_secs(approved_lifetime as u64);
                mapping_config.remap_interval = Duration::from_secs((approved_lifetime / 2) as u64);
                (approved_lifetime, opcode_data)
            },
        )
    }
}

impl Default for MappingTransactorReal {
    fn default() -> Self {
        MappingTransactorReal {
            logger: Logger::new("PcpTransactor"),
        }
    }
}

impl MappingTransactorReal {
    #[allow(clippy::type_complexity)]
    fn employ_factories(
        factories: &Factories,
        router_ip: IpAddr,
    ) -> (
        SocketAddr,
        io::Result<Box<dyn UdpSocketWrapper>>,
        Result<IpAddr, AutomapError>,
        [u8; 12],
    ) {
        let free_port = factories.free_port_factory.make();
        let socket_addr = make_local_socket_address(router_ip.is_ipv4(), free_port);
        (
            socket_addr,
            factories.socket_factory.make(socket_addr),
            factories.local_ip_finder.find(),
            factories.mapping_nonce_factory.make(),
        )
    }

    fn compute_mapping_result(
        response: PcpPacket,
        router_addr: SocketAddr,
        logger: &Logger,
    ) -> Result<(u32, MapOpcodeData), AutomapError> {
        let result_code = response
            .result_code_opt
            .expect("Response parsing inoperative - result code");
        if result_code != ResultCode::Success {
            let msg = format!("{:?}", result_code);
            return if result_code.is_permanent() {
                let e = AutomapError::PermanentMappingError(msg);
                warning!(logger, "Router at {} complained: \"{:?}\"", router_addr, e);
                Err(e)
            } else {
                let e = AutomapError::TemporaryMappingError(msg);
                warning!(logger, "Router at {} complained: \"{:?}\"", router_addr, e);
                Err(e)
            };
        }
        let approved_lifetime = response.lifetime;
        let opcode_data = response
            .opcode_data
            .as_any()
            .downcast_ref::<MapOpcodeData>()
            .expect("Response parsing inoperative - opcode data");
        Ok((approved_lifetime, opcode_data.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::pcp_pmp_common::{ANNOUNCEMENT_PORT, ROUTER_PORT};
    use crate::comm_layer::{AutomapErrorCause, LocalIpFinder};
    use crate::mocks::{FreePortFactoryMock, LocalIpFinderMock, TestMulticastSocketHolder, UdpSocketWrapperFactoryMock, UdpSocketWrapperMock};
    use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
    use crate::protocols::pcp::pcp_packet::{Opcode, PcpPacket};
    use crate::protocols::utils::{Direction, Packet, ParseError, UnrecognizedData};
    use core::ptr::addr_of;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::{find_free_port, localhost};
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::{io, thread};
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;

    pub struct MappingNonceFactoryMock {
        make_results: RefCell<Vec<[u8; 12]>>,
    }

    impl MappingNonceFactory for MappingNonceFactoryMock {
        fn make(&self) -> [u8; 12] {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl MappingNonceFactoryMock {
        pub fn new() -> Self {
            Self {
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_result(self, result: [u8; 12]) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    struct MappingTransactorMock {
        transact_params: Arc<Mutex<Vec<(*const (), SocketAddr, MappingConfig)>>>,
        transact_results: RefCell<Vec<Result<(u32, MapOpcodeData), AutomapError>>>,
    }

    unsafe impl Send for MappingTransactorMock {}

    impl MappingTransactor for MappingTransactorMock {
        fn transact(
            &self,
            factories: &Factories,
            router_addr: SocketAddr,
            mapping_config: &mut MappingConfig,
        ) -> Result<(u32, MapOpcodeData), AutomapError> {
            self.transact_params.lock().unwrap().push((
                addr_of!(*factories) as *const (),
                router_addr,
                mapping_config.clone(),
            ));
            if self.transact_results.borrow().len() > 1 {
                self.transact_results.borrow_mut().remove(0)
            } else {
                self.transact_results.borrow()[0].clone()
            }
        }
    }

    impl MappingTransactorMock {
        fn new() -> Self {
            Self {
                transact_params: Arc::new(Mutex::new(vec![])),
                transact_results: RefCell::new(vec![]),
            }
        }

        fn transact_params(
            mut self,
            params: &Arc<Mutex<Vec<(*const (), SocketAddr, MappingConfig)>>>,
        ) -> Self {
            self.transact_params = params.clone();
            self
        }

        // Note: the last result supplied will be returned over and over
        fn transact_result(self, result: Result<(u32, MapOpcodeData), AutomapError>) -> Self {
            self.transact_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn knows_its_method() {
        let subject = PcpTransactor::default();

        let method = subject.protocol();

        assert_eq!(method, AutomapProtocol::Pcp);
    }

    #[test]
    fn mapping_nonce_factory_works() {
        let mut value_sets: Vec<HashSet<u8>> =
            (0..12).into_iter().map(|_| HashSet::new()).collect();
        let subject = MappingNonceFactoryReal::new();

        // Generate ten nonces; collect all first bytes into one set, all second bytes into another, etc.
        for _ in 0..10 {
            let nonce = subject.make();
            for n in 0..12 {
                value_sets[n].insert(nonce[n]);
            }
        }

        // Make sure more than five different values were chosen for each byte
        for n in 0..12 {
            assert_eq!(
                value_sets[n].len() > 5,
                true,
                "Slot {}: {} values: {:?}",
                n,
                value_sets[n].len(),
                value_sets[n]
            );
        }
    }

    #[test]
    fn make_announcement_socket_failure_is_handled() {
        let mut subject = PcpTransactor::default();
        subject.announcement_multicast_group = 134;
        subject.announcement_port = 1234;
        let make_multicast_params_arc = Arc::new(Mutex::new(vec![]));
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_multicast_params(&make_multicast_params_arc)
            .make_multicast_result(Err(std::io::Error::from(ErrorKind::AddrInUse)));
        subject.inner().factories.socket_factory = Box::new (socket_factory);

        let result = subject.make_announcement_socket();

        assert_eq!(result.err().unwrap(), AutomapError::SocketBindingError(
            "Kind(AddrInUse)".to_string(),
            SocketAddr::new (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 134)),
                                        1234)
        ));
        let make_multicast_params = make_multicast_params_arc.lock().unwrap();
        assert_eq!(*make_multicast_params, vec![
            (134, 1234)
        ]);
    }

    #[test]
    fn mapping_transaction_handles_socket_factory_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.255").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Err(io_error));
        let free_port_factory = FreePortFactoryMock::new().make_result(5566);
        let subject = MappingTransactorReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);
        factories.free_port_factory = Box::new(free_port_factory);

        let result = subject
            .transact(
                &factories,
                SocketAddr::new(router_ip, ROUTER_PORT),
                &mut MappingConfig {
                    hole_port: 6666,
                    next_lifetime: Duration::from_secs(4321),
                    remap_interval: Duration::from_secs(2109),
                },
            )
            .err()
            .unwrap();

        match result {
            AutomapError::SocketBindingError(msg, addr) => {
                assert_eq!(msg, io_error_str);
                assert_eq!(addr.ip(), IpAddr::from_str("0.0.0.0").unwrap());
                assert_eq!(addr.port(), 5566);
            }
            e => panic!("Expected SocketBindingError, got {:?}", e),
        }
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PcpTransactor: Error while connecting to router at 0.0.0.0:5566: {:?}",
            io_error_str
        ));
    }

    #[test]
    fn mapping_transaction_handles_send_to_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.254").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Err(io_error));
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingTransactorReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.transact(
            &factories,
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Duration::from_secs(2109),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                io_error_str.clone()
            )))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PcpTransactor: Error while transmitting to router at {}:5351: {:?}",
            router_ip, io_error_str
        ));
    }

    #[test]
    fn mapping_transaction_handles_recv_from_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.253").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(Err(io_error), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingTransactorReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.transact(
            &factories,
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Duration::from_secs(2109),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::SocketReceiveError(
                AutomapErrorCause::Unknown(io_error_str.clone())
            ))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PcpTransactor: Error while receiving from router at {}:5351: {:?}",
            router_ip, io_error_str
        ));
    }

    #[test]
    fn mapping_transaction_handles_packet_parse_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.252").unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(Ok((0, SocketAddr::new(router_ip, ROUTER_PORT))), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingTransactorReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.transact(
            &factories,
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Duration::from_secs(2109),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::PacketParseError(ParseError::ShortBuffer(
                24, 0
            )))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PcpTransactor: Error while parsing packet from router at {}:5351: \"ShortBuffer(24, 0)\"",
            router_ip
        ));
    }

    #[test]
    fn mapping_transaction_handles_wrong_direction() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.251").unwrap();
        let mut buffer = [0u8; 1100];
        let packet = vanilla_request();
        let len = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((len, SocketAddr::new(router_ip, ROUTER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingTransactorReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.transact(
            &factories,
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Duration::from_secs(2109),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(
                "Map response labeled as request".to_string()
            ))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PcpTransactor: Router at {}:5351 is misbehaving: \"ProtocolError(\"Map response labeled as request\")\"",
            router_ip
        ));
    }

    #[test]
    fn mapping_transaction_handles_unexpected_opcode() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.250").unwrap();
        let mut buffer = [0u8; 1100];
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Other(127);
        let len = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((len, SocketAddr::new(router_ip, ROUTER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingTransactorReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.transact(
            &factories,
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Duration::from_secs(2109),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(
                "Map response has opcode Other(127) instead of Map".to_string()
            ))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PcpTransactor: Router at {}:5351 is misbehaving: \"ProtocolError(\"Map response has opcode Other(127) instead of Map\")\"",
            router_ip
        ));
    }

    #[test]
    fn find_routers_returns_something_believable() {
        let subject = PcpTransactor::default();

        let result = subject.find_routers().unwrap();

        assert!(result.len() > 0)
    }

    #[test]
    fn get_public_ip_works() {
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let mut request_packet = vanilla_request();
        request_packet.opcode = Opcode::Map;
        request_packet.lifetime = 0;
        let mut opcode_data = vanilla_map_request();
        opcode_data.internal_port = 9;
        opcode_data.external_port = 9;
        request_packet.opcode_data = opcode_data;
        let mut request = [0u8; 1100];
        let _request_len = request_packet.marshal(&mut request).unwrap();
        let mut response_packet = vanilla_response();
        response_packet.opcode = Opcode::Map;
        response_packet.lifetime = 0;
        response_packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = response_packet.marshal(&mut response).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let factories = &mut subject.inner_arc.lock().unwrap().factories;
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.get_public_ip(IpAddr::from_str("1.2.3.4").unwrap());

        assert_eq!(result, Ok(IpAddr::from_str("72.73.74.75").unwrap()));
        let send_to_params = send_to_params_arc.lock().unwrap();
        let (buffer, _socket_addr) = &send_to_params[0];
        let actual_request = PcpPacket::try_from(buffer.as_slice()).unwrap();
        assert_eq!(actual_request.direction, request_packet.direction);
        assert_eq!(actual_request.opcode, request_packet.opcode);
        assert_eq!(actual_request.lifetime, request_packet.lifetime);
        assert_eq!(actual_request.client_ip_opt, request_packet.client_ip_opt);
        assert_eq!(
            actual_request
                .opcode_data
                .as_any()
                .downcast_ref::<MapOpcodeData>(),
            request_packet
                .opcode_data
                .as_any()
                .downcast_ref::<MapOpcodeData>(),
        );
    }

    #[test]
    fn get_public_ip_handles_failure() {
        init_test_logging();
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.result_code_opt = Some(ResultCode::AddressMismatch);
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("192.168.0.249").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let factories = &mut subject.inner_arc.lock().unwrap().factories;
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.get_public_ip(IpAddr::from_str("192.168.0.249").unwrap());

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError(
                "AddressMismatch".to_string()
            ))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PcpTransactor: Router at 192.168.0.249:5351 complained: \"PermanentMappingError(\"AddressMismatch\")\"",
        ));
    }

    #[test]
    fn temporary_mapping_errors_are_handled() {
        init_test_logging();
        let mut response = vanilla_response();
        response.opcode = Opcode::Map;
        response.result_code_opt = Some(ResultCode::NoResources);
        response.lifetime = 0;
        response.opcode_data = vanilla_map_response();
        let router_addr = SocketAddr::from_str("192.168.0.248:5351").unwrap();
        let logger = Logger::new("PcpTransactor");

        let result = MappingTransactorReal::compute_mapping_result(response, router_addr, &logger);

        assert_eq!(
            result,
            Err(AutomapError::TemporaryMappingError(
                "NoResources".to_string()
            ))
        );
        TestLogHandler::new ().exists_log_containing (&format! (
            "WARN: PcpTransactor: Router at 192.168.0.248:5351 complained: \"TemporaryMappingError(\"NoResources\")\"",
        ));
    }

    #[test]
    fn add_mapping_works() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let set_read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let mut packet = vanilla_request();
        packet.opcode = Opcode::Map;
        packet.lifetime = 10000;
        packet.opcode_data = vanilla_map_request();
        let mut request = [0u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.opcode_data = vanilla_map_response();
        packet.lifetime = 8000;
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(1000))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let free_port_factory = FreePortFactoryMock::new().make_result(34567);
        let (tx, rx) = unbounded();
        let mut subject = PcpTransactor::default();
        subject.housekeeper_commander_opt = Some(tx);
        {
            let factories = &mut subject.inner_arc.lock().unwrap().factories;
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
            factories.free_port_factory = Box::new(free_port_factory);
        }

        let result = subject.add_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666, 10000);

        assert_eq!(result, Ok(4000));
        let mapping_config = match rx.try_recv().unwrap() {
            HousekeepingThreadCommand::InitializeMappingConfig(mc) => mc,
            x => panic!("Expecting AddMappingConfig, got {:?}", x),
        };
        assert_eq!(
            mapping_config,
            MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(8000),
                remap_interval: Duration::from_secs(4000),
            }
        );
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_str("0.0.0.0").unwrap(),
                34567
            ))]
        );
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq!(*set_read_timeout_params, vec![Some(Duration::from_secs(3))]);
        let mut send_to_params = send_to_params_arc.lock().unwrap();
        let (actual_buf, actual_addr) = send_to_params.remove(0);
        assert_eq!(
            format!("{:?}", PcpPacket::try_from(actual_buf.as_slice()).unwrap()),
            format!(
                "{:?}",
                PcpPacket::try_from(&request[0..request_len]).unwrap()
            )
        );
        assert_eq!(
            actual_addr,
            SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT)
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()]);
    }

    #[test]
    fn add_mapping_handles_failure() {
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.result_code_opt = Some(ResultCode::AddressMismatch);
        let opcode_data = vanilla_map_response();
        packet.opcode_data = opcode_data;
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let factories = &mut subject.inner_arc.lock().unwrap().factories;
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.add_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666, 1234);

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError(
                "AddressMismatch".to_string()
            ))
        );
    }

    #[test]
    #[should_panic(expected = "PCP cannot add permanent mappings")]
    fn add_permanent_mapping_is_not_implemented() {
        let subject = PcpTransactor::default();

        let _ = subject.add_permanent_mapping(IpAddr::from_str("0.0.0.0").unwrap(), 0);
    }

    #[test]
    fn delete_mapping_works() {
        let set_read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let mut packet = vanilla_request();
        packet.opcode = Opcode::Map;
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_request();
        let mut request = [0u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(1000))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let factories = &mut subject.inner_arc.lock().unwrap().factories;
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.delete_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666);

        assert_eq!(result, Ok(()));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq!(*set_read_timeout_params, vec![Some(Duration::from_secs(3))]);
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq!(
            *send_to_params,
            vec![(
                request[0..request_len].to_vec(),
                SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT)
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()]);
    }

    #[test]
    fn delete_mapping_handles_failure() {
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.result_code_opt = Some(ResultCode::NoResources);
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let factories = &mut subject.inner_arc.lock().unwrap().factories;
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.delete_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666);

        assert_eq!(
            result,
            Err(AutomapError::TemporaryMappingError(
                "NoResources".to_string()
            ))
        );
    }

    #[test]
    fn housekeeping_thread_works() {
        let _ = EnvironmentGuard::new();
        let announcement_port = find_free_port();
        let announce_socket_holder = TestMulticastSocketHolder::checkout(announcement_port);
        let router_port = find_free_port();
        let router_ip = localhost();
        let mut subject = PcpTransactor::default();
        subject.router_port = router_port;
        subject.announcement_multicast_group = announce_socket_holder.group;
        subject.announcement_port = announcement_port;
        let changes_arc = Arc::new(Mutex::new(vec![]));
        let changes_arc_inner = changes_arc.clone();
        let change_handler = move |change| {
            changes_arc_inner.lock().unwrap().push(change);
        };

        let commander = subject
            .start_housekeeping_thread(Box::new(change_handler), router_ip)
            .unwrap();

        commander
            .try_send(HousekeepingThreadCommand::InitializeMappingConfig(
                MappingConfig {
                    hole_port: 1234,
                    next_lifetime: Duration::from_secs(321),
                    remap_interval: Duration::from_secs(160),
                },
            ))
            .unwrap();
        let mut buffer = [0u8; 100];
        let announce_socket = &announce_socket_holder.socket;
        announce_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        announce_socket
            .connect(announce_socket.local_addr().unwrap())
            .unwrap();
        let mapping_socket = UdpSocket::bind(SocketAddr::new(localhost(), router_port)).unwrap();
        mapping_socket.set_read_timeout(Some (Duration::from_millis (1000))).unwrap();
        // Router announces to housekeeping thread that the public IP has changed
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Announce;
        packet.lifetime = 0;
        packet.epoch_time_opt = Some(0);
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let sent_len = announce_socket.send(&buffer[0..len_to_send]).unwrap();
        assert_eq!(sent_len, len_to_send);
        // Router receives mapping request from housekeeping thread to stimulate transmission of
        // new public IP address
        let (recv_len, remapping_socket_addr) = mapping_socket.recv_from(&mut buffer).unwrap();
        let packet = PcpPacket::try_from(&buffer[0..recv_len]).unwrap();
        assert_eq!(packet.opcode, Opcode::Map);
        assert_eq!(packet.lifetime, 321);
        let opcode_data: &MapOpcodeData = packet.opcode_data.as_any().downcast_ref().unwrap();
        assert_eq!(opcode_data.external_port, 1234);
        assert_eq!(opcode_data.internal_port, 1234);
        // Router sends mapping response to housekeeping thread to inform of new public IP address
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        let mut opcode_data = MapOpcodeData::default();
        opcode_data.external_ip_address = IpAddr::from_str("4.5.6.7").unwrap();
        packet.opcode_data = Box::new(opcode_data);
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let sent_len = mapping_socket
            .send_to(&buffer[0..len_to_send], remapping_socket_addr)
            .unwrap();
        assert_eq!(sent_len, len_to_send);
        thread::yield_now();
        let _ = subject.stop_housekeeping_thread();
        assert!(subject.housekeeper_commander_opt.is_none());
        let changes = changes_arc.lock().unwrap();
        assert_eq!(
            *changes,
            vec![AutomapChange::NewIp(IpAddr::from_str("4.5.6.7").unwrap())]
        )
    }

    #[test]
    fn housekeeping_thread_rejects_data_from_non_router_ip_addresses() {
        todo!();
        // let _ = EnvironmentGuard::new();
        // let change_handler_port = find_free_port();
        // let router_port = find_free_port();
        // let announcement_port = find_free_port();
        // let router_ip = IpAddr::from_str("7.7.7.7").unwrap();
        // let mut subject = PcpTransactor::default();
        // subject.router_port = router_port;
        // subject.announcement_multicast_group = change_handler_port;
        // let changes_arc = Arc::new(Mutex::new(vec![]));
        // let changes_arc_inner = changes_arc.clone();
        // let change_handler = move |change| {
        //     changes_arc_inner.lock().unwrap().push(change);
        // };
        //
        // subject
        //     .start_housekeeping_thread(Box::new(change_handler), router_ip)
        //     .unwrap();
        //
        // assert!(subject.housekeeper_commander_opt.is_some());
        // let change_handler_ip = IpAddr::from_str("224.0.0.1").unwrap();
        // todo! ("Replace this with a multicast socket");
        // let announce_socket =
        //     UdpSocket::bind(SocketAddr::new(localhost(), announcement_port)).unwrap();
        // announce_socket
        //     .set_read_timeout(Some(Duration::from_millis(1000)))
        //     .unwrap();
        // announce_socket.set_broadcast(true).unwrap();
        // announce_socket
        //     .connect(SocketAddr::new(change_handler_ip, change_handler_port))
        //     .unwrap();
        // let mut packet = vanilla_response();
        // packet.opcode = Opcode::Announce;
        // packet.lifetime = 0;
        // packet.epoch_time_opt = Some(0);
        // let mut buffer = [0u8; 100];
        // let len_to_send = packet.marshal(&mut buffer).unwrap();
        // let mapping_socket = UdpSocket::bind(SocketAddr::new(localhost(), router_port)).unwrap();
        // mapping_socket
        //     .set_read_timeout(Some(Duration::from_millis(100)))
        //     .unwrap();
        // let sent_len = announce_socket.send(&buffer[0..len_to_send]).unwrap();
        // assert_eq!(sent_len, len_to_send);
        // match mapping_socket.recv_from(&mut buffer) {
        //     Err(e) if (e.kind() == ErrorKind::TimedOut) || (e.kind() == ErrorKind::WouldBlock) => {
        //         ()
        //     }
        //     Err(e) => panic!("{:?}", e),
        //     Ok((recv_len, remapping_socket_addr)) => {
        //         let dump = pretty_hex(&buffer[0..recv_len].to_vec());
        //         panic!(
        //             "Should have timed out; but received from {}:\n{}",
        //             remapping_socket_addr, dump
        //         );
        //     }
        // }
        // let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn start_housekeeping_thread_doesnt_work_if_change_handler_stopper_is_populated() {
        let mut subject = PcpTransactor::default();
        subject.housekeeper_commander_opt = Some(unbounded().0);
        let change_handler = move |_| {};

        let result = subject.start_housekeeping_thread(Box::new(change_handler), localhost());

        assert_eq!(
            result.err().unwrap(),
            AutomapError::HousekeeperAlreadyRunning
        )
    }

    #[test]
    fn stop_housekeeping_thread_returns_same_change_handler_sent_into_start_housekeeping_thread() {
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_cla = change_log_arc.clone();
        let change_handler = Box::new(move |change| {
            let mut change_log = inner_cla.lock().unwrap();
            change_log.push(change)
        });
        let mut subject = PcpTransactor::default();
        let _ =
            subject.start_housekeeping_thread(change_handler, IpAddr::from_str("1.2.3.4").unwrap());

        let change_handler = subject.stop_housekeeping_thread().unwrap();

        let change = AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap());
        change_handler(change.clone());
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(change_log.last().unwrap(), &change)
    }

    #[test]
    #[should_panic(expected = "No HousekeepingCommander: can't stop housekeeping thread")]
    fn stop_housekeeping_thread_handles_missing_housekeeper_commander() {
        let mut subject = PcpTransactor::default();
        subject.housekeeper_commander_opt = None;

        let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn stop_housekeeping_thread_handles_broken_commander_connection() {
        init_test_logging();
        let mut subject = PcpTransactor::default();
        let (tx, rx) = unbounded();
        subject.housekeeper_commander_opt = Some(tx);
        std::mem::drop(rx);

        let result = subject.stop_housekeeping_thread().err().unwrap();

        assert_eq!(result, AutomapError::HousekeeperCrashed);
        TestLogHandler::new().exists_log_containing("WARN: PcpTransactor: Tried to stop housekeeping thread that had already disconnected from the commander");
    }

    #[test]
    #[should_panic(expected = "No JoinHandle: can't stop housekeeping thread")]
    fn stop_housekeeping_thread_handles_missing_join_handle() {
        let mut subject = PcpTransactor::default();
        let (tx, _rx) = unbounded();
        subject.housekeeper_commander_opt = Some(tx);
        subject.join_handle_opt = None;

        let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn stop_housekeeping_thread_handles_panicked_housekeeping_thread() {
        init_test_logging();
        let mut subject = PcpTransactor::default();
        let (tx, _rx) = unbounded();
        subject.housekeeper_commander_opt = Some(tx);
        subject.join_handle_opt = Some(thread::spawn(|| panic!("Booga!")));

        let result = subject.stop_housekeeping_thread().err().unwrap();

        assert_eq!(result, AutomapError::HousekeeperCrashed);
        TestLogHandler::new().exists_log_containing(
            "WARN: PcpTransactor: Tried to stop housekeeping thread that had panicked",
        );
    }

    #[test]
    fn thread_guts_does_not_remap_if_interval_does_not_run_out() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::TimedOut)), vec![]),
        );
        let socket_factory = Box::new(
            UdpSocketWrapperFactoryMock::new(), // no results specified; demanding one will fail the test
        );
        let mut factories = Factories::default();
        factories.socket_factory = socket_factory;
        let inner_arc = Arc::new(Mutex::new(PcpTransactorInner {
            mapping_transactor: Box::new(MappingTransactorReal::default()),
            factories,
        }));
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let mapping_config = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_secs(1),
            remap_interval: Duration::from_millis(500),
        };
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            mapping_config,
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(1000))
            .unwrap();
        tx.send(HousekeepingThreadCommand::Stop).unwrap();

        let _ = PcpTransactor::thread_guts(
            socket.as_ref(),
            &rx,
            inner_arc,
            SocketAddr::new(localhost(), 0),
            change_handler,
            10,
            Logger::new("no_remap_test"),
        );

        TestLogHandler::new().exists_no_log_containing("INFO: no_remap_test: Remapping port");
    }

    #[test]
    fn thread_guts_remaps_when_interval_runs_out() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let mapping_nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mapping_nonce_factory =
            Box::new(MappingNonceFactoryMock::new().make_result(mapping_nonce.clone()));
        let local_ip = IpAddr::from_str("192.168.0.100").unwrap();
        let local_ip_finder = Box::new(LocalIpFinderMock::new().find_result(Ok(local_ip)));
        let announcement_socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::WouldBlock)), vec![]),
        );
        let expected_outgoing_packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: 1000,
            client_ip_opt: Some(local_ip),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: mapping_nonce.clone(),
                protocol: Protocol::Tcp,
                internal_port: 6689,
                external_port: 6689,
                external_ip_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            }),
            options: vec![],
        };
        let mut expected_outgoing_packet_buf = [0u8; 100];
        let expected_outgoing_packet_length = expected_outgoing_packet
            .marshal(&mut expected_outgoing_packet_buf)
            .unwrap();
        let incoming_packet = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Map,
            result_code_opt: Some(ResultCode::Success),
            lifetime: 1000,
            client_ip_opt: None,
            epoch_time_opt: Some(4321),
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce,
                protocol: Protocol::Tcp,
                internal_port: 6689,
                external_port: 6689,
                external_ip_address: IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)),
            }),
            options: vec![],
        };
        let mut incoming_packet_buf = [0u8; 100];
        let incoming_packet_len = incoming_packet.marshal(&mut incoming_packet_buf).unwrap();
        let mapping_socket_send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_params(&mapping_socket_send_to_params_arc)
            .send_to_result(Ok(expected_outgoing_packet_length))
            .recv_from_result(
                Ok((
                    incoming_packet_len,
                    SocketAddr::from_str("1.2.3.4:5351").unwrap(),
                )),
                incoming_packet_buf[0..incoming_packet_len].to_vec(),
            );
        let socket_factory =
            Box::new(UdpSocketWrapperFactoryMock::new().make_result(Ok(mapping_socket)));
        let mut factories = Factories::default();
        factories.mapping_nonce_factory = mapping_nonce_factory;
        factories.local_ip_finder = local_ip_finder;
        factories.socket_factory = socket_factory;
        let inner_arc = Arc::new(Mutex::new(PcpTransactorInner {
            mapping_transactor: Box::new(MappingTransactorReal::default()),
            factories,
        }));
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let mapping_config = MappingConfig {
            hole_port: 6689,
            next_lifetime: Duration::from_secs(1000),
            remap_interval: Duration::from_secs(500),
        };
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            mapping_config,
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(80))
            .unwrap();

        let handle = thread::spawn(move || {
            let _ = PcpTransactor::thread_guts(
                announcement_socket.as_ref(),
                &rx,
                inner_arc,
                SocketAddr::new(localhost(), 0),
                change_handler,
                10,
                Logger::new("timed_remap_test"),
            );
        });

        thread::sleep(Duration::from_millis(100));
        tx.send(HousekeepingThreadCommand::Stop).unwrap();
        handle.join().unwrap();
        let mut mapping_socket_send_to_params = mapping_socket_send_to_params_arc.lock().unwrap();
        let (actual_outgoing_packet_bytes, _) = mapping_socket_send_to_params.remove(0);
        assert_eq!(
            actual_outgoing_packet_bytes,
            expected_outgoing_packet_buf[0..expected_outgoing_packet_length].to_vec(),
            "Was:\n{:?}\nbut should have been:\n{:?}",
            PcpPacket::try_from(actual_outgoing_packet_bytes.as_slice()).unwrap(),
            PcpPacket::try_from(&expected_outgoing_packet_buf[0..expected_outgoing_packet_length])
                .unwrap()
        );
        TestLogHandler::new().exists_log_containing("INFO: timed_remap_test: Remapping port 6689");
    }

    #[test]
    fn thread_guts_logs_if_error_receiving_pcp_packet() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::BrokenPipe)), vec![]),
        );
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let logger = Logger::new("thread_guts_logs_if_error_receiving_pcp_packet");
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_secs(u32::MAX as u64),
                remap_interval: Duration::from_secs((u32::MAX / 2) as u64),
            },
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::Stop).unwrap();

        let _ = PcpTransactor::thread_guts(
            socket.as_ref(),
            &rx,
            Arc::new(Mutex::new(PcpTransactorInner {
                mapping_transactor: Box::new(MappingTransactorReal::default()),
                factories: Factories::default(),
            })),
            SocketAddr::new(localhost(), 0),
            change_handler,
            10,
            logger,
        );

        TestLogHandler::new().exists_log_containing(
            "ERROR: thread_guts_logs_if_error_receiving_pcp_packet: Error receiving PCP packet from router: Kind(BrokenPipe)",
        );
    }

    #[test]
    fn thread_guts_logs_if_unparseable_pcp_packet_arrives() {
        init_test_logging();
        let socket_addr = SocketAddr::from_str("1.1.1.1:1").unwrap();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Ok((5, socket_addr)), b"booga".to_vec()),
        );
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let logger = Logger::new("thread_guts_logs_if_unparseable_pcp_packet_arrives");
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_secs(u32::MAX as u64),
                remap_interval: Duration::from_secs((u32::MAX / 2) as u64),
            },
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::Stop).unwrap();

        let _ = PcpTransactor::thread_guts(
            socket.as_ref(),
            &rx,
            Arc::new(Mutex::new(PcpTransactorInner {
                mapping_transactor: Box::new(MappingTransactorReal::default()),
                factories: Factories::default(),
            })),
            SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 0),
            change_handler,
            10,
            logger,
        );

        TestLogHandler::new().exists_log_containing(
            "ERROR: thread_guts_logs_if_unparseable_pcp_packet_arrives: Unparseable PCP packet:",
        );
    }

    #[test]
    fn thread_guts_logs_and_continues_if_remap_interval_is_set_before_mapping_config() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(std::io::Error::from(ErrorKind::WouldBlock)), vec![]),
        );
        let mapping_transactor = Box::new(MappingTransactorMock::new().transact_result(Err(
            AutomapError::TemporaryMappingError("NoResources".to_string()),
        )));
        let logger = Logger::new(
            "thread_guts_logs_and_continues_if_remap_interval_is_set_before_mapping_config",
        );
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(80))
            .unwrap();
        tx.send(HousekeepingThreadCommand::Stop).unwrap();

        let handle = thread::spawn(move || {
            let _ = PcpTransactor::thread_guts(
                socket.as_ref(),
                &rx,
                Arc::new(Mutex::new(PcpTransactorInner {
                    mapping_transactor,
                    factories: Factories::default(),
                })),
                SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 0),
                Box::new(|_| ()),
                10,
                logger,
            );
        });

        handle.join().unwrap();
        TestLogHandler::new ().exists_log_containing(
            "ERROR: thread_guts_logs_and_continues_if_remap_interval_is_set_before_mapping_config: Can't set remap interval until after first mapping request"
        );
    }

    #[test]
    fn thread_guts_logs_and_continues_if_announcement_is_received_before_mapping_config() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let mut announce_packet = vanilla_response();
        announce_packet.opcode = Opcode::Announce;
        announce_packet.lifetime = 0;
        let mut announce_buf = [0u8; 100];
        let announce_packet_len = announce_packet.marshal(&mut announce_buf).unwrap();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(
                    Ok((
                        announce_packet_len,
                        SocketAddr::from_str("1.1.1.1:1111").unwrap(),
                    )),
                    announce_buf.to_vec(),
                ),
        );
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_cla = change_log_arc.clone();
        let change_handler = Box::new(move |change| {
            let mut change_log = inner_cla.lock().unwrap();
            change_log.push(change)
        });
        let mapping_transactor = Box::new(
            MappingTransactorMock::new().transact_result(Ok((1111, *vanilla_map_response()))),
        );
        let logger = Logger::new(
            "thread_guts_logs_and_continues_if_announcement_is_received_before_mapping_config",
        );

        let handle = thread::spawn(move || {
            let _ = PcpTransactor::thread_guts(
                socket.as_ref(),
                &rx,
                Arc::new(Mutex::new(PcpTransactorInner {
                    mapping_transactor,
                    factories: Factories::default(),
                })),
                SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 0),
                change_handler,
                10,
                logger,
            );
        });

        thread::sleep(Duration::from_millis(100));
        tx.send(HousekeepingThreadCommand::Stop).unwrap();
        handle.join().unwrap();
        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(
            *change_log,
            vec![AutomapChange::NewIp(
                IpAddr::from_str("72.73.74.75").unwrap()
            )]
        );
        TestLogHandler::new ().exists_log_containing(
            "DEBUG: thread_guts_logs_and_continues_if_announcement_is_received_before_mapping_config: Received announcement that public IP address changed to 72.73.74.75"
        );
    }

    #[test]
    fn thread_guts_complains_if_remapping_fails() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::TimedOut)), b"".to_vec()),
        );
        let mapping_transactor = Box::new(
            MappingTransactorMock::new()
                .transact_result(Err(AutomapError::TemporaryMappingError(
                    "NoResources".to_string(),
                )))
                .transact_result(Ok((0, MapOpcodeData::default()))), // extra fodder for macOS in Actions
        );
        let change_opt_arc = Arc::new(Mutex::new(None));
        let change_opt_arc_inner = change_opt_arc.clone();
        let change_handler: ChangeHandler = Box::new(move |change| {
            change_opt_arc_inner.lock().unwrap().replace(change);
        });
        let logger = Logger::new("thread_guts_complains_if_remapping_fails");
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_secs(u32::MAX as u64),
                remap_interval: Duration::from_secs((u32::MAX / 2) as u64),
            },
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(80))
            .unwrap();

        let handle = thread::spawn(move || {
            let _ = PcpTransactor::thread_guts(
                socket.as_ref(),
                &rx,
                Arc::new(Mutex::new(PcpTransactorInner {
                    mapping_transactor,
                    factories: Factories::default(),
                })),
                SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 0),
                change_handler,
                10,
                logger,
            );
        });

        thread::sleep(Duration::from_millis(100));
        tx.send(HousekeepingThreadCommand::Stop).unwrap();
        handle.join().unwrap();
        let change_opt = change_opt_arc.lock().unwrap();
        assert_eq!(
            *change_opt,
            Some(AutomapChange::Error(AutomapError::TemporaryMappingError(
                "NoResources".to_string()
            )))
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: thread_guts_complains_if_remapping_fails: Remapping failure: TemporaryMappingError(\"NoResources\")",
        );
    }

    #[test]
    fn handle_announcement_logs_if_remapping_fails() {
        init_test_logging();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(
            UdpSocketWrapperFactoryMock::new()
                .make_result(Err(io::Error::from(ErrorKind::AlreadyExists))),
        );
        factories.free_port_factory = Box::new(FreePortFactoryMock::new().make_result(2345));
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let change_log_inner = change_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_log_inner.lock().unwrap().push(change));
        let mapping_config = MappingConfig {
            hole_port: 0,
            next_lifetime: Default::default(),
            remap_interval: Default::default(),
        };
        let logger = Logger::new("handle_announcement_logs_if_remapping_fails");
        let mapping_transactor = Box::new(MappingTransactorReal::default());
        let inner = PcpTransactorInner {
            mapping_transactor,
            factories,
        };

        PcpTransactor::handle_announcement(
            &inner,
            SocketAddr::new(localhost(), 0),
            &change_handler,
            &mut Some(mapping_config),
            &logger,
        );

        let change_log = change_log_arc.lock().unwrap();
        assert_eq!(
            *change_log,
            vec![AutomapChange::Error(AutomapError::SocketBindingError(
                "Kind(AlreadyExists)".to_string(),
                SocketAddr::from_str("0.0.0.0:2345").unwrap()
            ))]
        );
        TestLogHandler::new().exists_log_containing ("ERROR: handle_announcement_logs_if_remapping_fails: Remapping after IP change failed, Node is useless: SocketBindingError(\"Kind(AlreadyExists)\", 0.0.0.0:2345");
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_greater_than_one_second() {
        let mapping_transactor_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_transactor = MappingTransactorMock::new()
            .transact_params(&mapping_transactor_params_arc)
            .transact_result(Err(AutomapError::Unknown));
        let inner = PcpTransactorInner {
            mapping_transactor: Box::new(mapping_transactor),
            factories: Factories::default(),
        };

        let result = PcpTransactor::remap_port(
            &inner,
            SocketAddr::new(localhost(), 0),
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Default::default(),
                remap_interval: Default::default(),
            },
            Duration::from_millis(100900),
            &Logger::new("test"),
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut mapping_transactor_params = mapping_transactor_params_arc.lock().unwrap();
        let requested_lifetime: u32 = mapping_transactor_params.remove(0).2.next_lifetime_secs();
        assert_eq!(requested_lifetime, 100);
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_less_than_one_second() {
        let mapping_transactor_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_transactor = MappingTransactorMock::new()
            .transact_params(&mapping_transactor_params_arc)
            .transact_result(Err(AutomapError::Unknown));
        let inner = PcpTransactorInner {
            mapping_transactor: Box::new(mapping_transactor),
            factories: Factories::default(),
        };
        let mut mapping_config = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(500),
            remap_interval: Duration::from_millis(0),
        };

        let result = PcpTransactor::remap_port(
            &inner,
            SocketAddr::new(localhost(), 0),
            &mut mapping_config,
            Duration::from_millis(80),
            &Logger::new("test"),
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut mapping_transactor_params = mapping_transactor_params_arc.lock().unwrap();
        let requested_lifetime: u32 = mapping_transactor_params.remove(0).2.next_lifetime_secs();
        assert_eq!(requested_lifetime, 1);
    }

    #[test]
    fn remap_port_handles_mapping_failure() {
        let mapping_transactor = MappingTransactorMock::new().transact_result(Err(
            AutomapError::PermanentMappingError("MalformedRequest".to_string()),
        ));
        let inner = PcpTransactorInner {
            mapping_transactor: Box::new(mapping_transactor),
            factories: Factories::default(),
        };
        let mut mapping_config = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(0),
            remap_interval: Duration::from_millis(0),
        };

        let result = PcpTransactor::remap_port(
            &inner,
            SocketAddr::new(localhost(), 0),
            &mut mapping_config,
            Duration::from_millis(1000),
            &Logger::new("test"),
        );

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError(
                "MalformedRequest".to_string()
            ))
        );
        assert_eq!(
            mapping_config,
            MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_millis(1000),
                remap_interval: Duration::from_millis(0),
            }
        )
    }

    fn vanilla_request() -> PcpPacket {
        PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Other(127),
            result_code_opt: None,
            lifetime: 1234,
            client_ip_opt: Some(LocalIpFinderReal::new().find().unwrap()),
            epoch_time_opt: None,
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        }
    }

    fn vanilla_response() -> PcpPacket {
        PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Other(127),
            result_code_opt: Some(ResultCode::Success),
            lifetime: 1234,
            client_ip_opt: None,
            epoch_time_opt: Some(4321),
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        }
    }

    fn vanilla_map_request() -> Box<MapOpcodeData> {
        Box::new(MapOpcodeData {
            mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            protocol: Protocol::Tcp,
            internal_port: 6666,
            external_port: 6666,
            external_ip_address: IpAddr::from_str("0.0.0.0").unwrap(),
        })
    }

    fn vanilla_map_response() -> Box<MapOpcodeData> {
        Box::new(MapOpcodeData {
            mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            protocol: Protocol::Tcp,
            internal_port: 6666,
            external_port: 6666,
            external_ip_address: IpAddr::from_str("72.73.74.75").unwrap(),
        })
    }

    #[test]
    fn play_with_multicast() {
        // make three sockets
        // Note: for some reason, at least on Dan's machine, Ipv4Addr::UNSPECIFIED is the only value
        // that works here. Anything definite will fail because the receiving socket can't hear
        // the sending socket. There shouldn't be any security threat in using UNSPECIFIED, because
        // multicast addresses are not routed out to the Internet; but this is still puzzling.
        let multicast_interface = Ipv4Addr::UNSPECIFIED;
        let multicast_address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 122)),
            find_free_port()
        );
        let make_socket = || {
            let socket =
                Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            //linux/macos have reuse_port exposed so we can flag it for non-windows systems
            #[cfg(not(target_os = "windows"))]
            socket.set_reuse_port(true).unwrap();
            //windows has reuse_port hidden and implicitly flagged with reuse_address
            socket.set_reuse_address(true).unwrap();
            let multicast_ipv4 = match multicast_address.ip() {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(addr) => panic! ("Multicast IP is IPv6! {}", addr)
            };
            socket
                .join_multicast_v4(
                    &multicast_ipv4,
                    &multicast_interface)
                .unwrap();
            socket.bind(
                &SockAddr::from(
                    SocketAddr::new(
                        IpAddr::from(multicast_interface),
                        multicast_address.port()
                    )
                )
            ).unwrap();
            UdpSocket::from(socket)
        };
        let socket_sender = make_socket();
        let socket_receiver_1 = make_socket();
        let socket_receiver_2 = make_socket();
        let message = b"Taxation is theft!";
        socket_sender.send_to(message, multicast_address).unwrap();
        let mut buf = [0u8; 100];
        let (size, source) = socket_receiver_1.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], message);
        let (size, source) = socket_receiver_2.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], message);
    }
}
