// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{
    find_routers, make_local_socket_address, FreePortFactory, FreePortFactoryReal, MappingConfig,
    UdpSocketFactoryReal, UdpSocketWrapper, UdpSocketWrapperFactory, ANNOUNCEMENT_PORT,
    ANNOUNCEMENT_READ_TIMEOUT_MILLIS, ROUTER_PORT,
};
use crate::comm_layer::{AutomapError, AutomapErrorCause, HousekeepingThreadCommand, Transactor};
use crate::control_layer::automap_control::{AutomapChange, ChangeHandler};
use crate::protocols::pmp::get_packet::GetOpcodeData;
use crate::protocols::pmp::map_packet::MapOpcodeData;
use crate::protocols::pmp::pmp_packet::{Opcode, PmpPacket, ResultCode};
use crate::protocols::utils::{Direction, Packet};
use crossbeam_channel::{unbounded, Receiver, Sender};
use masq_lib::logger::Logger;
use masq_lib::utils::AutomapProtocol;
use masq_lib::{debug, error, info, warning};
use pretty_hex::PrettyHex;
use std::any::Any;
use std::convert::TryFrom;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PMP_READ_TIMEOUT_MS: u64 = 3000;

struct Factories {
    socket_factory: Box<dyn UdpSocketWrapperFactory>,
    free_port_factory: Box<dyn FreePortFactory>,
}

impl Default for Factories {
    fn default() -> Self {
        Self {
            socket_factory: Box::new(UdpSocketFactoryReal::new()),
            free_port_factory: Box::new(FreePortFactoryReal::new()),
        }
    }
}

pub struct PmpTransactor {
    mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>>,
    factories_arc: Arc<Mutex<Factories>>,
    router_port: u16,
    listen_port: u16,
    housekeeper_commander_opt: Option<Sender<HousekeepingThreadCommand>>,
    join_handle_opt: Option<JoinHandle<ChangeHandler>>,
    read_timeout_millis: u64,
    logger: Logger,
}

impl Transactor for PmpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        debug!(self.logger, "Seeking routers on LAN");
        find_routers()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        debug!(
            self.logger,
            "Seeking public IP from router at {}", router_ip
        );
        let request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: None,
            }),
        };
        let response = Self::transact(
            &self.factories_arc,
            SocketAddr::new(router_ip, self.router_port),
            &request,
            PMP_READ_TIMEOUT_MS,
            &self.logger,
        )?;
        match response
            .result_code_opt
            .expect("transact allowed absent result code")
        {
            ResultCode::Success => (),
            rc => return Err(AutomapError::TransactionFailure(format!("{:?}", rc))),
        }
        let opcode_data = response
            .opcode_data
            .as_any()
            .downcast_ref::<GetOpcodeData>()
            .expect("Response parsing inoperative - opcode data");
        let ip = opcode_data
            .external_ip_address_opt
            .expect("Response parsing inoperative - external IP address");
        Ok(IpAddr::V4(ip))
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
        let mut mapping_config = MappingConfig {
            hole_port,
            next_lifetime: Duration::from_secs(lifetime as u64),
            remap_interval: Duration::from_secs(0),
        };
        self.mapping_adder_arc
            .lock()
            .expect("Housekeeping thread is dead")
            .add_mapping(
                &self.factories_arc,
                SocketAddr::new(router_ip, self.router_port),
                &mut mapping_config,
            )
            .map(|remap_interval| {
                self.housekeeper_commander_opt
                    .as_ref()
                    .expect("Housekeeping thread is dead")
                    .send(HousekeepingThreadCommand::InitializeMappingConfig(
                        mapping_config,
                    ))
                    .expect("Housekeeping thread is dead");
                remap_interval
            })
    }

    fn add_permanent_mapping(
        &self,
        _router_ip: IpAddr,
        _hole_port: u16,
    ) -> Result<u32, AutomapError> {
        panic!("PMP cannot add permanent mappings")
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        debug!(
            self.logger,
            "Deleting mapping of port {} through router at {}", hole_port, router_ip
        );
        self.add_mapping(router_ip, hole_port, 0)?;
        Ok(())
    }

    fn protocol(&self) -> AutomapProtocol {
        AutomapProtocol::Pmp
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
        if let Some(_housekeeper_commander) = &self.housekeeper_commander_opt {
            return Err(AutomapError::HousekeeperAlreadyRunning);
        }
        let announce_ip_addr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
        let announce_socket_addr = SocketAddr::new(announce_ip_addr, self.listen_port);
        let announce_socket_result = {
            let factories = self.factories_arc.lock().expect("Automap is poisoned!");
            factories.socket_factory.make(announce_socket_addr)
        };
        let announcement_socket = match announce_socket_result {
            Ok(s) => s,
            Err(e) => {
                return Err(AutomapError::SocketBindingError(
                    format!("{:?}", e),
                    announce_socket_addr,
                ))
            }
        };
        let (tx, rx) = unbounded();
        self.housekeeper_commander_opt = Some(tx.clone());
        let thread_guts = ThreadGuts::new(self, router_ip, announcement_socket, change_handler, rx);
        self.join_handle_opt = Some(thread_guts.go());
        Ok(tx)
    }

    fn stop_housekeeping_thread(&mut self) -> Result<ChangeHandler, AutomapError> {
        debug!(self.logger, "Stopping housekeeping thread");
        let commander = self
            .housekeeper_commander_opt
            .take()
            .expect("No HousekeepingCommander: can't stop housekeeping thread");
        let change_handler = match commander.send(HousekeepingThreadCommand::Stop) {
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

impl Default for PmpTransactor {
    fn default() -> Self {
        Self {
            mapping_adder_arc: Arc::new(Mutex::new(Box::new(MappingAdderReal::default()))),
            factories_arc: Arc::new(Mutex::new(Factories::default())),
            router_port: ROUTER_PORT,
            listen_port: ANNOUNCEMENT_PORT,
            housekeeper_commander_opt: None,
            read_timeout_millis: ANNOUNCEMENT_READ_TIMEOUT_MILLIS,
            join_handle_opt: None,
            logger: Logger::new("PmpTransactor"),
        }
    }
}

impl PmpTransactor {
    pub fn new() -> Self {
        Self::default()
    }

    fn transact(
        factories_arc: &Arc<Mutex<Factories>>,
        router_addr: SocketAddr,
        request: &PmpPacket,
        read_timeout_ms: u64,
        logger: &Logger,
    ) -> Result<PmpPacket, AutomapError> {
        let mut buffer = [0u8; 1100];
        let len = request
            .marshal(&mut buffer)
            .expect("Bad packet construction");
        let socket = {
            let factories = factories_arc.lock().expect("Factories are dead");
            let local_address = make_local_socket_address(
                router_addr.ip().is_ipv4(),
                factories.free_port_factory.make(),
            );
            match factories.socket_factory.make(local_address) {
                Ok(s) => s,
                Err(e) => {
                    warning!(
                        logger,
                        "Error creating UDP socket at {}: \"{:?}\"",
                        local_address,
                        e
                    );
                    return Err(AutomapError::SocketBindingError(
                        format!("{:?}", e),
                        local_address,
                    ));
                }
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))
            .expect("set_read_timeout failed");
        if let Err(e) = socket.send_to(&buffer[0..len], router_addr) {
            warning!(
                logger,
                "Error transmitting to router at {}: \"{:?}\"",
                router_addr,
                e
            );
            return Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                format!("{:?}", e),
            )));
        }
        let (len, _) = match socket.recv_from(&mut buffer) {
            Ok(len) => len,
            Err(e) if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) => {
                return Err(AutomapError::ProtocolError(format!(
                    "Timed out after {}ms",
                    read_timeout_ms
                )))
            }
            Err(e) => {
                warning!(
                    logger,
                    "Error receiving from router at {}: \"{:?}\"",
                    router_addr,
                    e
                );
                return Err(AutomapError::SocketReceiveError(
                    AutomapErrorCause::Unknown(format!("{:?}", e)),
                ));
            }
        };
        let response = match PmpPacket::try_from(&buffer[0..len]) {
            Ok(pkt) => pkt,
            Err(e) => {
                warning!(
                    logger,
                    "Error parsing packet from router at {}: \"{:?}\"",
                    router_addr,
                    e
                );
                return Err(AutomapError::PacketParseError(e));
            }
        };
        Ok(response)
    }
}

struct ThreadGuts {
    announcement_socket: Box<dyn UdpSocketWrapper>,
    housekeeper_flunkie: Receiver<HousekeepingThreadCommand>,
    mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>>,
    factories_arc: Arc<Mutex<Factories>>,
    router_addr: SocketAddr,
    change_handler: ChangeHandler,
    announcement_read_timeout_millis: u64,
    logger: Logger,
}

impl ThreadGuts {
    pub fn new(
        transactor: &PmpTransactor,
        router_ip: IpAddr,
        announcement_socket: Box<dyn UdpSocketWrapper>,
        change_handler: ChangeHandler,
        housekeeper_flunkie: Receiver<HousekeepingThreadCommand>,
    ) -> Self {
        Self {
            announcement_socket,
            housekeeper_flunkie,
            mapping_adder_arc: transactor.mapping_adder_arc.clone(),
            factories_arc: transactor.factories_arc.clone(),
            router_addr: SocketAddr::new(router_ip, transactor.router_port),
            change_handler,
            announcement_read_timeout_millis: transactor.read_timeout_millis,
            logger: transactor.logger.clone(),
        }
    }

    pub fn go(self) -> JoinHandle<ChangeHandler> {
        thread::spawn(move || self.thread_guts())
    }

    fn thread_guts(mut self) -> ChangeHandler {
        let mut last_remapped = Instant::now();
        let mut mapping_config_opt = None;
        self.announcement_socket
            .set_read_timeout(Some(Duration::from_millis(
                self.announcement_read_timeout_millis,
            )))
            .expect("Can't set read timeout");
        while self.thread_guts_iteration(&mut mapping_config_opt, &mut last_remapped) {}
        self.change_handler
    }

    fn thread_guts_iteration(
        &mut self,
        mapping_config_opt: &mut Option<MappingConfig>,
        last_remapped: &mut Instant,
    ) -> bool {
        if self.handle_announcement_if_present(mapping_config_opt) {
            return true;
        }
        if let Some(mapping_config) = mapping_config_opt {
            self.maybe_remap(mapping_config, last_remapped);
        }
        match self.housekeeper_flunkie.try_recv() {
            Ok(HousekeepingThreadCommand::Stop) => return false,
            Ok(HousekeepingThreadCommand::SetRemapIntervalMs(remap_after)) => {
                mapping_config_opt
                    .map(|mut mc| mc.remap_interval = Duration::from_millis(remap_after));
            }
            Ok(HousekeepingThreadCommand::InitializeMappingConfig(mapping_config)) => {
                mapping_config_opt.replace(mapping_config);
            }
            Err(_) => (),
        };
        true
    }

    fn handle_announcement_if_present(&self, mapping_config_opt: &Option<MappingConfig>) -> bool {
        let mut buffer = [0u8; 100];
        // This will block for awhile, conserving CPU cycles
        debug!(&self.logger, "Waiting for an IP-change announcement");
        match self.announcement_socket.recv_from(&mut buffer) {
            Ok((_, announcement_source_address)) => {
                if announcement_source_address.ip() != self.router_addr.ip() {
                    return true;
                }
                match self.parse_buffer(&buffer, announcement_source_address) {
                    Ok(public_ip) => {
                        self.handle_announcement(public_ip, mapping_config_opt);
                        false
                    }
                    Err(_) => true, // log already generated by parse_buffer()
                }
            }
            Err(e) if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) => {
                false
            }
            Err(e) => {
                error!(
                    &self.logger,
                    "Error receiving PCP packet from router: {:?}", e
                );
                false
            }
        }
    }

    fn maybe_remap(&self, mapping_config: &mut MappingConfig, last_remapped: &mut Instant) {
        let since_last_remapped = last_remapped.elapsed();
        if since_last_remapped.gt(&mapping_config.remap_interval) {
            let mapping_adder = self
                .mapping_adder_arc
                .lock()
                .expect("PmpTransactor is dead");
            if let Err(e) = self.remap_port(mapping_adder.as_ref(), mapping_config) {
                error!(
                    &self.logger,
                    "Automatic PMP remapping failed for port {}: {:?})",
                    mapping_config.hole_port,
                    e
                );
                self.change_handler.as_ref()(AutomapChange::Error(e));
            }
            *last_remapped = Instant::now();
        }
    }

    fn parse_buffer(
        &self,
        buffer: &[u8],
        source_address: SocketAddr,
    ) -> Result<Ipv4Addr, AutomapError> {
        match PmpPacket::try_from(buffer) {
            Ok(packet) => {
                if packet.direction != Direction::Response {
                    let err_msg = format!(
                        "Unexpected PMP Get request (request!) from router at {}: ignoring",
                        source_address
                    );
                    warning!(&self.logger, "{}", err_msg);
                    return Err(AutomapError::ProtocolError(err_msg));
                }
                if packet.opcode == Opcode::Get {
                    let opcode_data = packet
                        .opcode_data
                        .as_any()
                        .downcast_ref::<GetOpcodeData>()
                        .expect("A Get opcode shouldn't parse anything but GetOpcodeData");
                    Ok(opcode_data
                        .external_ip_address_opt
                        .expect("A Response should always produce an external ip address"))
                } else {
                    let err_msg = format!(
                        "Unexpected PMP {:?} response (instead of Get) from router at {}: ignoring",
                        packet.opcode, source_address
                    );
                    warning!(&self.logger, "{}", err_msg);
                    Err(AutomapError::ProtocolError(err_msg))
                }
            }
            Err(e) => {
                error!(
                    &self.logger,
                    "Unparseable PMP packet ({:?}):\n{}",
                    &e,
                    PrettyHex::hex_dump(&buffer)
                );
                let err_msg = format!(
                    "Unparseable packet ({:?}) from router at {}: ignoring",
                    &e, source_address
                );
                warning!(
                    &self.logger,
                    "{}\n{}",
                    err_msg,
                    PrettyHex::hex_dump(&buffer)
                );
                Err(AutomapError::ProtocolError(err_msg))
            }
        }
    }

    fn handle_announcement(&self, public_ip: Ipv4Addr, mapping_config_opt: &Option<MappingConfig>) {
        match mapping_config_opt {
            Some(mapping_config) => {
                let mut packet = PmpPacket {
                    opcode: Opcode::MapTcp,
                    direction: Direction::Request,
                    ..Default::default()
                };
                let opcode_data = MapOpcodeData {
                    epoch_opt: None,
                    internal_port: mapping_config.hole_port,
                    external_port: mapping_config.hole_port,
                    lifetime: mapping_config.next_lifetime_secs(),
                };
                packet.opcode_data = Box::new(opcode_data);
                debug!(
                    &self.logger,
                    "Sending mapping request to {} and waiting for response", self.router_addr
                );
                match PmpTransactor::transact(
                    &self.factories_arc,
                    self.router_addr,
                    &packet,
                    PMP_READ_TIMEOUT_MS,
                    &self.logger,
                ) {
                    Ok(response) => match response.result_code_opt {
                        Some(ResultCode::Success) => {
                            debug!(
                                &self.logger,
                                "Remapping successful; triggering change handler"
                            );
                            self.change_handler.as_ref()(AutomapChange::NewIp(IpAddr::V4(
                                public_ip,
                            )));
                        }
                        Some(result_code) => {
                            let err_msg = format!(
                                "Remapping after IP change failed; Node is useless: {:?}",
                                result_code
                            );
                            error!(&self.logger, "{}\n{:?}", err_msg, packet);
                            let automap_error = if result_code.is_permanent() {
                                AutomapError::PermanentMappingError(err_msg)
                            } else {
                                AutomapError::TemporaryMappingError(err_msg)
                            };
                            self.change_handler.as_ref()(AutomapChange::Error(automap_error));
                        }
                        None => {
                            let err_msg = "Remapping after IP change failed; Node is useless: Received request when expecting response".to_string();
                            error!(&self.logger, "{}\n{:?}", err_msg, packet);
                            self.change_handler.as_ref()(AutomapChange::Error(
                                AutomapError::ProtocolError(err_msg),
                            ));
                        }
                    },
                    Err(e) => {
                        error!(
                            &self.logger,
                            "Remapping after IP change failed; Node is useless: {:?}", e
                        );
                        self.change_handler.as_ref()(AutomapChange::Error(
                            AutomapError::SocketReceiveError(AutomapErrorCause::SocketFailure),
                        ));
                    }
                }
            }
            None => {
                debug!(
                    &self.logger,
                    "Public IP change detected; triggering change handler"
                );
                self.change_handler.as_ref()(AutomapChange::NewIp(IpAddr::V4(public_ip)));
            }
        }
    }

    fn remap_port(
        &self,
        mapping_adder: &dyn MappingAdder,
        mapping_config: &mut MappingConfig,
    ) -> Result<u32, AutomapError> {
        info!(&self.logger, "Remapping port {}", mapping_config.hole_port);
        if mapping_config.next_lifetime.as_millis() < 1000 {
            mapping_config.next_lifetime = Duration::from_millis(1000);
        }
        mapping_adder.add_mapping(&self.factories_arc, self.router_addr, mapping_config)
    }
}

trait MappingAdder: Send {
    fn add_mapping(
        &self,
        factories_arc: &Arc<Mutex<Factories>>,
        router_addr: SocketAddr,
        mapping_config: &mut MappingConfig,
    ) -> Result<u32, AutomapError>;
}

#[derive(Clone)]
struct MappingAdderReal {
    logger: Logger,
}

impl Default for MappingAdderReal {
    fn default() -> Self {
        Self {
            logger: Logger::new("PmpTransactor"),
        }
    }
}

impl MappingAdder for MappingAdderReal {
    fn add_mapping(
        &self,
        factories_arc: &Arc<Mutex<Factories>>,
        router_addr: SocketAddr,
        mapping_config: &mut MappingConfig,
    ) -> Result<u32, AutomapError> {
        debug!(
            self.logger,
            "Adding mapping for port {} through router at {} for {}ms",
            mapping_config.hole_port,
            router_addr,
            mapping_config.next_lifetime.as_millis(),
        );
        let request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::MapTcp,
            result_code_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                epoch_opt: None,
                internal_port: mapping_config.hole_port,
                external_port: mapping_config.hole_port,
                lifetime: mapping_config.next_lifetime_secs(),
            }),
        };
        let response = PmpTransactor::transact(
            factories_arc,
            router_addr,
            &request,
            PMP_READ_TIMEOUT_MS,
            &self.logger,
        )?;
        if response.direction == Direction::Request {
            let e = AutomapError::ProtocolError("Map response labeled as request".to_string());
            warning!(
                self.logger,
                "Router at {} is misbehaving: \"{:?}\"",
                router_addr,
                e
            );
            return Err(e);
        }
        if response.opcode != Opcode::MapTcp {
            let e = AutomapError::ProtocolError(format!(
                "Expected MapTcp response; got {:?} response instead of MapTcp",
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
        let opcode_data: &MapOpcodeData = response
            .opcode_data
            .as_any()
            .downcast_ref()
            .expect("MapTcp response contained other than MapOpcodeData");
        match response
            .result_code_opt
            .expect("transact allowed absent result code")
        {
            ResultCode::Success => {
                mapping_config.next_lifetime = Duration::from_secs(opcode_data.lifetime as u64);
                mapping_config.remap_interval =
                    Duration::from_secs((opcode_data.lifetime / 2) as u64);
                Ok(opcode_data.lifetime / 2)
            }
            rc => {
                let msg = format!("{:?}", rc);
                Err(if rc.is_permanent() {
                    AutomapError::PermanentMappingError(msg)
                } else {
                    AutomapError::TemporaryMappingError(msg)
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::pcp_pmp_common::{MappingConfig, UdpSocket};
    use crate::comm_layer::AutomapErrorCause;
    use crate::control_layer::automap_control::AutomapChange;
    use crate::mocks::{FreePortFactoryMock, UdpSocketWrapperFactoryMock, UdpSocketWrapperMock};
    use crate::protocols::pmp::get_packet::GetOpcodeData;
    use crate::protocols::pmp::map_packet::MapOpcodeData;
    use crate::protocols::pmp::pmp_packet::{Opcode, PmpOpcodeData, PmpPacket, ResultCode};
    use crate::protocols::utils::{Direction, Packet, ParseError, UnrecognizedData};
    use lazy_static::lazy_static;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::{find_free_port, localhost, AutomapProtocol};
    use std::cell::RefCell;
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::ops::Sub;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::{io, thread};
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;

    lazy_static! {
        static ref ROUTER_ADDR: SocketAddr = SocketAddr::from_str("1.2.3.4:5351").unwrap();
        static ref PUBLIC_IP: IpAddr = IpAddr::from_str("2.3.4.5").unwrap();
    }

    struct MappingAdderMock {
        add_mapping_params: Arc<Mutex<Vec<(Arc<Mutex<Factories>>, SocketAddr, MappingConfig)>>>,
        add_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
    }

    impl MappingAdder for MappingAdderMock {
        fn add_mapping(
            &self,
            factories_arc: &Arc<Mutex<Factories>>,
            router_addr: SocketAddr,
            mapping_config: &mut MappingConfig,
        ) -> Result<u32, AutomapError> {
            let result = self.add_mapping_results.borrow_mut().remove(0);
            if let Ok(remap_interval) = &result {
                mapping_config.remap_interval = Duration::from_secs(*remap_interval as u64);
            }
            self.add_mapping_params.lock().unwrap().push((
                factories_arc.clone(),
                router_addr,
                mapping_config.clone(),
            ));
            result
        }
    }

    impl MappingAdderMock {
        fn new() -> Self {
            Self {
                add_mapping_params: Default::default(),
                add_mapping_results: Default::default(),
            }
        }

        fn add_mapping_params(
            mut self,
            params: &Arc<Mutex<Vec<(Arc<Mutex<Factories>>, SocketAddr, MappingConfig)>>>,
        ) -> Self {
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
        let subject = PmpTransactor::new();

        let method = subject.protocol();

        assert_eq!(method, AutomapProtocol::Pmp);
    }

    #[test]
    fn transact_handles_socket_binding_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.255").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionReset);
        let io_error_str = format!("{:?}", io_error);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Err(io_error));
        let subject = make_subject(socket_factory);

        let result = subject.get_public_ip(router_ip).err().unwrap();

        match result {
            AutomapError::SocketBindingError(msg, addr) => {
                assert_eq!(msg, io_error_str);
                assert_eq!(addr, SocketAddr::from_str("0.0.0.0:5566").unwrap());
            }
            e => panic!("Expected SocketBindingError, got {:?}", e),
        }
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PmpTransactor: Error creating UDP socket at 0.0.0.0:5566: {:?}",
            io_error_str
        ));
    }

    #[test]
    fn transact_handles_socket_send_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.254").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionReset);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Err(io_error));
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_subject(socket_factory);

        let result = subject.add_mapping(router_ip, 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                io_error_str.clone()
            )))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PmpTransactor: Error transmitting to router at {}:5351: {:?}",
            router_ip, io_error_str
        ));
    }

    #[test]
    fn transact_handles_socket_receive_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.253").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionReset);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(24))
            .recv_from_result(Err(io_error), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_subject(socket_factory);

        let result = subject.add_mapping(router_ip, 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::SocketReceiveError(
                AutomapErrorCause::Unknown(io_error_str.clone())
            ))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PmpTransactor: Error receiving from router at {}:5351: {:?}",
            router_ip, io_error_str
        ));
    }

    #[test]
    fn transact_handles_packet_parse_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.252").unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(24))
            .recv_from_result(Ok((0, SocketAddr::new(router_ip, ROUTER_PORT))), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = PmpTransactor::default();
        subject.factories_arc.lock().unwrap().socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(router_ip, 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::PacketParseError(ParseError::ShortBuffer(
                2, 0
            )))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PmpTransactor: Error parsing packet from router at {}:5351: \"ShortBuffer(2, 0)\"",
            router_ip
        ));
    }

    #[test]
    fn find_routers_returns_something_believable() {
        let subject = PmpTransactor::default();

        let result = subject.find_routers().unwrap();

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn add_mapping_handles_socket_factory_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.249").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Err(io_error));
        let free_port_factory = FreePortFactoryMock::new().make_result(5566);
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);
        factories.free_port_factory = Box::new(free_port_factory);

        let result = subject
            .add_mapping(
                &Arc::new(Mutex::new(factories)),
                SocketAddr::new(router_ip, ROUTER_PORT),
                &mut MappingConfig {
                    hole_port: 6666,
                    next_lifetime: Duration::from_secs(4321),
                    remap_interval: Default::default(),
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
            "WARN: PmpTransactor: Error creating UDP socket at 0.0.0.0:5566: {:?}",
            io_error_str
        ));
    }

    #[test]
    fn add_mapping_handles_send_to_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.248").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Err(io_error));
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &Arc::new(Mutex::new(factories)),
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                io_error_str.clone()
            )))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PmpTransactor: Error transmitting to router at {}:5351: {:?}",
            router_ip, io_error_str
        ));
    }

    #[test]
    fn add_mapping_handles_recv_from_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.247").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(Err(io_error), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &Arc::new(Mutex::new(factories)),
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::SocketReceiveError(
                AutomapErrorCause::Unknown(io_error_str.clone())
            ))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: PmpTransactor: Error receiving from router at {}:5351: {:?}",
            router_ip, io_error_str
        ));
    }

    #[test]
    fn add_mapping_handles_packet_parse_error() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.246").unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(Ok((0, SocketAddr::new(router_ip, ROUTER_PORT))), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &Arc::new(Mutex::new(factories)),
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::PacketParseError(ParseError::ShortBuffer(
                2, 0
            )))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PmpTransactor: Error parsing packet from router at {}:5351: \"ShortBuffer(2, 0)\"",
            router_ip
        ));
    }

    #[test]
    fn add_mapping_handles_wrong_direction() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.251").unwrap();
        let mut buffer = [0u8; 1100];
        let packet = make_request(Opcode::Other(127), Box::new(UnrecognizedData::new()));
        let len = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((len, SocketAddr::new(router_ip, ROUTER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &Arc::new(Mutex::new(factories)),
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(
                "Map response labeled as request".to_string()
            ))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PmpTransactor: Router at {}:5351 is misbehaving: \"ProtocolError(\"Map response labeled as request\")\"",
            router_ip
        ));
    }

    #[test]
    fn add_mapping_handles_unexpected_opcode() {
        init_test_logging();
        let router_ip = IpAddr::from_str("192.168.0.250").unwrap();
        let mut buffer = [0u8; 1100];
        let mut packet = make_response(
            Opcode::Other(127),
            ResultCode::Success,
            Box::new(UnrecognizedData::new()),
        );
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
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &Arc::new(Mutex::new(factories)),
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(4321),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(
                "Expected MapTcp response; got Other(127) response instead of MapTcp".to_string()
            ))
        );
        TestLogHandler::new ().exists_log_containing(&format! (
            "WARN: PmpTransactor: Router at {}:5351 is misbehaving: \"ProtocolError(\"Expected MapTcp response; got Other(127) response instead of MapTcp\")\"",
            router_ip
        ));
    }

    #[test]
    fn add_mapping_modifies_mapping_config_upon_mapping() {
        let router_ip = IpAddr::from_str("192.168.0.250").unwrap();
        let mut buffer = [0u8; 1100];
        let packet = make_response(
            Opcode::MapTcp,
            ResultCode::Success,
            make_map_response(0, 6666, 1234),
        );
        let len = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((len, SocketAddr::new(router_ip, ROUTER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);
        let mut mapping_config = MappingConfig {
            hole_port: 6666,
            next_lifetime: Duration::from_secs(4321),
            remap_interval: Default::default(),
        };

        let result = subject.add_mapping(
            &Arc::new(Mutex::new(factories)),
            SocketAddr::new(router_ip, ROUTER_PORT),
            &mut mapping_config,
        );

        assert_eq!(result, Ok(617));
        assert_eq!(
            mapping_config,
            MappingConfig {
                hole_port: 6666,
                next_lifetime: Duration::from_secs(1234),
                remap_interval: Duration::from_secs(617),
            }
        );
    }

    #[test]
    fn get_public_ip_works() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let public_ip = Ipv4Addr::from_str("72.73.74.75").unwrap();
        let mut request_buffer = [0u8; 1100];
        let request = make_request(Opcode::Get, make_get_request());
        let request_len = request.marshal(&mut request_buffer).unwrap();
        let mut response_buffer = [0u8; 1100];
        let response = make_response(
            Opcode::Get,
            ResultCode::Success,
            make_get_response(1234, public_ip),
        );
        let response_len = response.marshal(&mut response_buffer).unwrap();
        let set_read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(request_len))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_subject(socket_factory);

        let result = subject.get_public_ip(router_ip);

        assert_eq!(result, Ok(IpAddr::V4(public_ip)));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq!(
            *set_read_timeout_params,
            vec![Some(Duration::from_millis(3000))]
        );
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq!(
            *send_to_params,
            vec![(
                request_buffer[0..request_len].to_vec(),
                SocketAddr::new(router_ip, ROUTER_PORT)
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()])
    }

    #[test]
    fn get_public_ip_handles_unsuccessful_result_code() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let public_ip = Ipv4Addr::from_str("72.73.74.75").unwrap();
        let mut response_buffer = [0u8; 1100];
        let mut response = make_response(
            Opcode::Get,
            ResultCode::Success,
            make_get_response(1234, public_ip),
        );
        response.result_code_opt = Some(ResultCode::OutOfResources);
        let response_len = response.marshal(&mut response_buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(24))
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_subject(socket_factory);

        let result = subject.get_public_ip(router_ip);

        assert_eq!(
            result,
            Err(AutomapError::TransactionFailure(
                "OutOfResources".to_string()
            ))
        );
    }

    #[test]
    fn add_mapping_works() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let mut request_buffer = [0u8; 1100];
        let request = make_request(Opcode::MapTcp, make_map_request(7777, 10));
        let request_len = request.marshal(&mut request_buffer).unwrap();
        let mut response_buffer = [0u8; 1100];
        let response = make_response(
            Opcode::MapTcp,
            ResultCode::Success,
            make_map_response(4321, 7777, 8),
        );
        let response_len = response.marshal(&mut response_buffer).unwrap();
        let set_read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let announcement_socket = UdpSocketWrapperMock::new();
        let main_socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(request_len))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_result(Ok(announcement_socket))
            .make_result(Ok(main_socket));
        let mut subject = make_subject(socket_factory);
        subject
            .start_housekeeping_thread(Box::new(|_| ()), router_ip)
            .unwrap();

        let result = subject.add_mapping(router_ip, 7777, 10);

        let _ = subject.stop_housekeeping_thread();
        assert_eq!(result, Ok(4));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq!(
            *set_read_timeout_params,
            vec![Some(Duration::from_millis(3000))]
        );
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq!(
            *send_to_params,
            vec![(
                request_buffer[0..request_len].to_vec(),
                SocketAddr::new(router_ip, ROUTER_PORT)
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()])
    }

    #[test]
    fn add_mapping_handles_temporarily_unsuccessful_result_code() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let mut response_buffer = [0u8; 1100];
        let mut response = make_response(
            Opcode::MapTcp,
            ResultCode::Success,
            make_map_response(4321, 7777, 1234),
        );
        response.result_code_opt = Some(ResultCode::OutOfResources);
        let response_len = response.marshal(&mut response_buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(24))
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_subject(socket_factory);

        let result = subject.add_mapping(router_ip, 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::TemporaryMappingError(
                "OutOfResources".to_string()
            ))
        );
    }

    #[test]
    fn add_mapping_handles_permanently_unsuccessful_result_code() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let mut response_buffer = [0u8; 1100];
        let mut response = make_response(
            Opcode::MapTcp,
            ResultCode::Success,
            make_map_response(4321, 7777, 1234),
        );
        response.result_code_opt = Some(ResultCode::UnsupportedOpcode);
        let response_len = response.marshal(&mut response_buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(24))
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_subject(socket_factory);

        let result = subject.add_mapping(router_ip, 7777, 1234);

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError(
                "UnsupportedOpcode".to_string()
            ))
        );
    }

    #[test]
    #[should_panic(expected = "PMP cannot add permanent mappings")]
    fn add_permanent_mapping_is_not_implemented() {
        let subject = PmpTransactor::default();

        let _ = subject.add_permanent_mapping(IpAddr::from_str("0.0.0.0").unwrap(), 0);
    }

    #[test]
    fn delete_mapping_works() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let mut request_buffer = [0u8; 1100];
        let request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::MapTcp,
            result_code_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                epoch_opt: None,
                internal_port: 7777,
                external_port: 7777,
                lifetime: 0,
            }),
        };
        let request_len = request.marshal(&mut request_buffer).unwrap();
        let mut response_buffer = [0u8; 1100];
        let response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::MapTcp,
            result_code_opt: Some(ResultCode::Success),
            opcode_data: Box::new(MapOpcodeData {
                epoch_opt: Some(4321),
                internal_port: 7777,
                external_port: 7777,
                lifetime: 0,
            }),
        };
        let response_len = response.marshal(&mut response_buffer).unwrap();
        let set_read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let announcement_socket = UdpSocketWrapperMock::new();
        let main_socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(request_len))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_result(Ok(announcement_socket))
            .make_result(Ok(main_socket));
        let mut subject = make_subject(socket_factory);
        subject
            .start_housekeeping_thread(Box::new(|_| ()), router_ip)
            .unwrap();

        let result = subject.delete_mapping(router_ip, 7777);

        let _ = subject.stop_housekeeping_thread();
        assert_eq!(result, Ok(()));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq!(
            *set_read_timeout_params,
            vec![Some(Duration::from_millis(3000))]
        );
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq!(
            *send_to_params,
            vec![(
                request_buffer[0..request_len].to_vec(),
                SocketAddr::new(router_ip, ROUTER_PORT)
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()])
    }

    #[test]
    fn housekeeping_thread_works() {
        let _ = EnvironmentGuard::new();
        let announcement_port = find_free_port();
        let router_port = find_free_port();
        let announce_port = find_free_port();
        let mapping_adder = MappingAdderMock::new().add_mapping_result(Ok(1000));
        let mut subject = PmpTransactor::default();
        subject.router_port = router_port;
        subject.listen_port = announcement_port;
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(mapping_adder)));
        subject.read_timeout_millis = 10;
        let mapping_config = MappingConfig {
            hole_port: 1234,
            next_lifetime: Duration::from_millis(321),
            remap_interval: Duration::from_millis(0),
        };
        let changes_arc = Arc::new(Mutex::new(vec![]));
        let changes_arc_inner = changes_arc.clone();
        let change_handler = move |change| {
            changes_arc_inner.lock().unwrap().push(change);
        };

        subject
            .start_housekeeping_thread(Box::new(change_handler), localhost())
            .unwrap();

        subject
            .housekeeper_commander_opt
            .as_ref()
            .unwrap()
            .send(HousekeepingThreadCommand::InitializeMappingConfig(
                mapping_config,
            ))
            .unwrap();
        thread::sleep(Duration::from_millis(50)); // wait for first announcement read to time out
        let announcement_ip = IpAddr::from_str("224.0.0.1").unwrap();
        let announce_socket = UdpSocket::bind(SocketAddr::new(localhost(), announce_port)).unwrap();
        announce_socket.set_broadcast(true).unwrap();
        announce_socket
            .connect(SocketAddr::new(announcement_ip, announcement_port))
            .unwrap();
        let mut packet = PmpPacket::default();
        packet.opcode = Opcode::Get;
        packet.direction = Direction::Response;
        packet.result_code_opt = Some(ResultCode::Success);
        packet.opcode_data = make_get_response(0, Ipv4Addr::from_str("1.2.3.4").unwrap());
        let mut buffer = [0u8; 100];
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let mapping_target_address = SocketAddr::new(localhost(), router_port);
        let mapping_socket = UdpSocket::bind(mapping_target_address).unwrap();
        let sent_len = announce_socket.send(&buffer[0..len_to_send]).unwrap();
        assert_eq!(sent_len, len_to_send);
        mapping_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        let (recv_len, remapping_socket_addr) = mapping_socket.recv_from(&mut buffer).unwrap();
        let packet = PmpPacket::try_from(&buffer[0..recv_len]).unwrap();
        assert_eq!(packet.opcode, Opcode::MapTcp);
        let opcode_data: &MapOpcodeData = packet.opcode_data.as_any().downcast_ref().unwrap();
        assert_eq!(opcode_data.external_port, 1234);
        assert_eq!(opcode_data.internal_port, 1234);
        let mut packet = PmpPacket::default();
        packet.opcode = Opcode::MapTcp;
        packet.direction = Direction::Response;
        packet.result_code_opt = Some(ResultCode::Success);
        packet.opcode_data = make_map_response(0, 1234, 1000);
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let sent_len = mapping_socket
            .send_to(&buffer[0..len_to_send], remapping_socket_addr)
            .unwrap();
        assert_eq!(sent_len, len_to_send);
        thread::sleep(Duration::from_millis(1)); // yield timeslice
        let _ = subject.stop_housekeeping_thread();
        assert!(subject.housekeeper_commander_opt.is_none());
        let changes = changes_arc.lock().unwrap();
        assert_eq!(
            *changes,
            vec![AutomapChange::NewIp(IpAddr::from_str("1.2.3.4").unwrap())]
        );
    }

    #[test]
    fn housekeeping_thread_rejects_data_from_non_router_ip_addresses() {
        let _ = EnvironmentGuard::new();
        let announcement_receive_port = find_free_port();
        let router_port = find_free_port();
        let announcement_send_port = find_free_port();
        let router_ip = IpAddr::from_str("7.7.7.7").unwrap();
        let mapping_adder = MappingAdderMock::new().add_mapping_result(Ok(1000));
        let mut subject = PmpTransactor::default();
        subject.router_port = router_port;
        subject.listen_port = announcement_receive_port;
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(mapping_adder)));
        let mapping_config = MappingConfig {
            hole_port: 1234,
            next_lifetime: Duration::from_millis(321),
            remap_interval: Duration::from_millis(0),
        };
        let changes_arc = Arc::new(Mutex::new(vec![]));
        let changes_arc_inner = changes_arc.clone();
        let change_handler = move |change| {
            changes_arc_inner.lock().unwrap().push(change);
        };

        let tx = subject
            .start_housekeeping_thread(Box::new(change_handler), router_ip)
            .unwrap();

        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            mapping_config,
        ))
        .unwrap();
        assert!(subject.housekeeper_commander_opt.is_some());
        let announcement_receive_ip = IpAddr::from_str("224.0.0.1").unwrap();
        let announcement_send_socket = UdpSocket::bind(SocketAddr::new(localhost(), announcement_send_port)).unwrap();
        announcement_send_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        announcement_send_socket.set_broadcast(true).unwrap();
        announcement_send_socket
            .connect(SocketAddr::new(announcement_receive_ip, announcement_receive_port))
            .unwrap();
        let mut packet = PmpPacket::default();
        packet.opcode = Opcode::Get;
        packet.direction = Direction::Response;
        packet.result_code_opt = Some(ResultCode::Success);
        packet.opcode_data = make_get_response(0, Ipv4Addr::from_str("1.2.3.4").unwrap());
        let mut buffer = [0u8; 100];
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let sent_len = announcement_send_socket.send(&buffer[0..len_to_send]).unwrap();
        assert_eq!(sent_len, len_to_send);
        thread::sleep(Duration::from_millis(1)); // yield timeslice
        let _ = subject.stop_housekeeping_thread();
        assert!(subject.housekeeper_commander_opt.is_none());
        let changes = changes_arc.lock().unwrap();
        assert_eq!(*changes, vec![]);
    }

    #[test]
    fn housekeeping_thread_rejects_data_that_causes_parse_errors() {
        let _ = EnvironmentGuard::new();
        init_test_logging();
        let change_handler_port = find_free_port();
        let router_port = find_free_port();
        let announce_port = find_free_port();
        let router_ip = localhost();
        let mapping_adder = MappingAdderMock::new().add_mapping_result(Ok(1000));
        let mut subject = PmpTransactor::default();
        subject.router_port = router_port;
        subject.listen_port = change_handler_port;
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(mapping_adder)));
        let mapping_config = MappingConfig {
            hole_port: 1234,
            next_lifetime: Duration::from_millis(321),
            remap_interval: Duration::from_millis(0),
        };
        let changes_arc = Arc::new(Mutex::new(vec![]));
        let changes_arc_inner = changes_arc.clone();
        let change_handler = move |change| {
            changes_arc_inner.lock().unwrap().push(change);
        };

        let tx = subject
            .start_housekeeping_thread(Box::new(change_handler), router_ip)
            .unwrap();

        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            mapping_config,
        ))
        .unwrap();
        assert!(subject.housekeeper_commander_opt.is_some());
        let change_handler_ip = IpAddr::from_str("224.0.0.1").unwrap();
        let announce_socket = UdpSocket::bind(SocketAddr::new(localhost(), announce_port)).unwrap();
        announce_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        announce_socket.set_broadcast(true).unwrap();
        announce_socket
            .connect(SocketAddr::new(change_handler_ip, change_handler_port))
            .unwrap();
        let mut packet = PmpPacket::default();
        packet.opcode = Opcode::Get;
        packet.direction = Direction::Request; // should be Response
        packet.result_code_opt = Some(ResultCode::Success);
        packet.opcode_data = make_get_response(0, Ipv4Addr::from_str("1.2.3.4").unwrap());
        let mut buffer = [0u8; 100];
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let sent_len = announce_socket.send(&buffer[0..len_to_send]).unwrap();
        assert_eq!(sent_len, len_to_send);
        thread::sleep(Duration::from_millis(1)); // yield timeslice
        let _ = subject.stop_housekeeping_thread();
        assert!(subject.housekeeper_commander_opt.is_none());
        let changes = changes_arc.lock().unwrap();
        assert_eq!(*changes, vec![]);
        let err_msg = "Unexpected PMP Get request (request!) from router at ";
        TestLogHandler::new().exists_log_containing(&format!("WARN: PmpTransactor: {}", err_msg));
    }

    #[test]
    fn stop_housekeeping_thread_returns_same_change_handler_sent_into_start_housekeeping_thread() {
        let change_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_cla = change_log_arc.clone();
        let change_handler = Box::new(move |change| {
            let mut change_log = inner_cla.lock().unwrap();
            change_log.push(change)
        });
        let mapping_adder = MappingAdderMock::new().add_mapping_result(Ok(1000));
        let mut subject = PmpTransactor::default();
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(mapping_adder)));
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
        let mut subject = PmpTransactor::default();
        subject.housekeeper_commander_opt = None;

        let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn stop_housekeeping_thread_handles_broken_commander_connection() {
        init_test_logging();
        let mut subject = PmpTransactor::default();
        let (tx, rx) = unbounded();
        subject.housekeeper_commander_opt = Some(tx);
        std::mem::drop(rx);

        let result = subject.stop_housekeeping_thread().err().unwrap();

        assert_eq!(result, AutomapError::HousekeeperCrashed);
        TestLogHandler::new().exists_log_containing("WARN: PmpTransactor: Tried to stop housekeeping thread that had already disconnected from the commander");
    }

    #[test]
    #[should_panic(expected = "No JoinHandle: can't stop housekeeping thread")]
    fn stop_housekeeping_thread_handles_missing_join_handle() {
        let mut subject = PmpTransactor::default();
        let (tx, _rx) = unbounded();
        subject.housekeeper_commander_opt = Some(tx);
        subject.join_handle_opt = None;

        let _ = subject.stop_housekeeping_thread();
    }

    #[test]
    fn stop_housekeeping_thread_handles_panicked_housekeeping_thread() {
        init_test_logging();
        let mut subject = PmpTransactor::default();
        let (tx, _rx) = unbounded();
        subject.housekeeper_commander_opt = Some(tx);
        subject.join_handle_opt = Some(thread::spawn(|| panic!("Booga!")));

        let result = subject.stop_housekeeping_thread().err().unwrap();

        assert_eq!(result, AutomapError::HousekeeperCrashed);
        TestLogHandler::new().exists_log_containing(
            "WARN: PmpTransactor: Tried to stop housekeeping thread that had panicked",
        );
    }

    #[test]
    fn thread_guts_does_not_remap_if_interval_does_not_run_out() {
        init_test_logging();
        let announcement_socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::TimedOut)), vec![]),
        );
        let (tx, rx) = unbounded();
        let mapping_adder: Box<dyn MappingAdder> = Box::new(MappingAdderMock::new()); // no results specified
        let mapping_config = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_secs(20),
            remap_interval: Duration::from_secs(10),
        };
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            announcement_socket,
            Box::new(move |_| {}),
            rx,
        );
        subject.mapping_adder_arc = Arc::new(Mutex::new(mapping_adder));
        subject.logger = Logger::new("no_remap_test");
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            mapping_config,
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(10000))
            .unwrap();
        tx.send(HousekeepingThreadCommand::Stop).unwrap();

        let _ = subject.thread_guts();

        TestLogHandler::new().exists_no_log_containing("INFO: no_remap_test: Remapping port");
    }

    #[test]
    fn thread_guts_remaps_when_interval_runs_out() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>> = Arc::new(Mutex::new(Box::new(
            MappingAdderMock::new()
                .add_mapping_params(&add_mapping_params_arc)
                .add_mapping_result(Ok(300)),
        )));
        let free_port_factory = FreePortFactoryMock::new().make_result(5555);
        let mut factories = Factories::default();
        factories.free_port_factory = Box::new(free_port_factory);
        let announcement_socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketWrapperMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::WouldBlock)), vec![]),
        );
        let mapping_config = MappingConfig {
            hole_port: 6689,
            next_lifetime: Duration::from_secs(1000),
            remap_interval: Duration::from_millis(80),
        };
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            announcement_socket,
            Box::new(move |_| {}),
            rx,
        );
        subject.mapping_adder_arc = mapping_adder_arc;
        subject.factories_arc = Arc::new(Mutex::new(factories));
        subject.logger = Logger::new("timed_remap_test");
        tx.send(HousekeepingThreadCommand::InitializeMappingConfig(
            mapping_config,
        ))
        .unwrap();
        tx.send(HousekeepingThreadCommand::SetRemapIntervalMs(80))
            .unwrap();

        let handle = subject.go();

        thread::sleep(Duration::from_millis(100));
        tx.send(HousekeepingThreadCommand::Stop).unwrap();
        let _ = handle.join().unwrap();
        let add_mapping_params = add_mapping_params_arc.lock().unwrap().remove(0);
        assert_eq!(
            add_mapping_params
                .0
                .lock()
                .unwrap()
                .free_port_factory
                .make(),
            5555
        );
        assert_eq!(add_mapping_params.1, *ROUTER_ADDR);
        assert_eq!(
            add_mapping_params.2,
            MappingConfig {
                hole_port: 6689,
                next_lifetime: Duration::from_secs(1000),
                remap_interval: Duration::from_secs(300)
            }
        );
        TestLogHandler::new().exists_log_containing("INFO: timed_remap_test: Remapping port 6689");
    }

    #[test]
    fn maybe_remap_handles_remapping_error() {
        init_test_logging();
        let mapping_adder: Box<dyn MappingAdder> = Box::new(
            MappingAdderMock::new()
                .add_mapping_result(Err(AutomapError::ProtocolError("Booga".to_string()))),
        );
        let mapping_adder_arc = Arc::new(Mutex::new(mapping_adder));
        let router_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let change_records = vec![];
        let change_records_arc = Arc::new(Mutex::new(change_records));
        let change_records_arc_inner = change_records_arc.clone();
        let change_handler: ChangeHandler = Box::new(move |change| {
            change_records_arc_inner.lock().unwrap().push(change);
        });
        let mut mapping_config = MappingConfig {
            hole_port: 6689,
            next_lifetime: Duration::from_secs(600),
            remap_interval: Duration::from_secs(0),
        };
        let mut last_remapped = Instant::now().sub(Duration::from_secs(3600));
        let logger = Logger::new("maybe_remap_handles_remapping_error");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_addr.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            change_handler,
            unbounded().1,
        );
        subject.mapping_adder_arc = mapping_adder_arc;
        // subject.factories_arc = factories_arc;
        subject.logger = logger;

        subject.maybe_remap(&mut mapping_config, &mut last_remapped);

        let change_records = change_records_arc.lock().unwrap();
        assert_eq!(
            *change_records,
            vec![AutomapChange::Error(AutomapError::ProtocolError(
                "Booga".to_string()
            ))]
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: maybe_remap_handles_remapping_error: Automatic PMP remapping failed for port 6689: ProtocolError(\"Booga\")"
        );
    }

    #[test]
    fn parse_buffer_rejects_request_packet() {
        init_test_logging();
        let router_ip = IpAddr::from_str("4.3.2.1").unwrap();
        let mut packet = PmpPacket::default();
        packet.opcode = Opcode::Get;
        packet.direction = Direction::Request;
        let mut buffer = [0u8; 100];
        let buflen = packet.marshal(&mut buffer).unwrap();
        let logger = Logger::new("parse_buffer_rejects_request_packet");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_ip,
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );
        subject.logger = logger;

        let result = subject.parse_buffer(&buffer[0..buflen], SocketAddr::new(router_ip, 5351));

        let err_msg = "Unexpected PMP Get request (request!) from router at 4.3.2.1:5351: ignoring";
        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(err_msg.to_string()))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: parse_buffer_rejects_request_packet: {}",
            err_msg
        ));
    }

    #[test]
    fn parse_buffer_rejects_packet_other_than_get() {
        init_test_logging();
        let router_ip = IpAddr::from_str("4.3.2.1").unwrap();
        let mut packet = PmpPacket::default();
        packet.opcode = Opcode::MapUdp;
        packet.direction = Direction::Response;
        packet.opcode_data = Box::new(MapOpcodeData::default());
        let mut buffer = [0u8; 100];
        let buflen = packet.marshal(&mut buffer).unwrap();
        let logger = Logger::new("parse_buffer_rejects_packet_other_than_get");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_ip,
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );
        subject.logger = logger;

        let result = subject.parse_buffer(&buffer[0..buflen], SocketAddr::new(router_ip, 5351));

        let err_msg =
            "Unexpected PMP MapUdp response (instead of Get) from router at 4.3.2.1:5351: ignoring";
        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(err_msg.to_string()))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: parse_buffer_rejects_packet_other_than_get: {}",
            err_msg
        ));
    }

    #[test]
    fn parse_buffer_rejects_unparseable_packet() {
        init_test_logging();
        let router_ip = IpAddr::from_str("4.3.2.1").unwrap();
        let buffer = [0xFFu8; 100];
        let logger = Logger::new("parse_buffer_rejects_unparseable_packet");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_ip,
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );
        subject.logger = logger;

        let result = subject.parse_buffer(
            &buffer[0..2], // wayyy too short
            SocketAddr::new(router_ip, 5351),
        );

        let err_msg =
            "Unparseable packet (WrongVersion(255)) from router at 4.3.2.1:5351: ignoring";
        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(err_msg.to_string()))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: parse_buffer_rejects_unparseable_packet: {}",
            err_msg
        ));
    }

    #[test]
    fn handle_announcement_processes_transaction_failure() {
        init_test_logging();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(100))
            .recv_from_result(Err(io::Error::from(ErrorKind::ConnectionReset)), vec![]);
        let factories = Factories {
            socket_factory: Box::new(UdpSocketWrapperFactoryMock::new().make_result(Ok(socket))),
            free_port_factory: Box::new(FreePortFactoryMock::new().make_result(1234)),
        };
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_inner = change_handler_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_handler_log_inner.lock().unwrap().push(change));
        let logger = Logger::new("test");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            change_handler,
            unbounded().1,
        );
        subject.router_addr = *ROUTER_ADDR;
        subject.factories_arc = Arc::new(Mutex::new(factories));
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(MappingAdderMock::new())));
        subject.logger = logger;

        subject.handle_announcement(
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
            &mut Some(MappingConfig {
                hole_port: 2222,
                next_lifetime: Duration::from_secs(10),
                remap_interval: Duration::from_secs(0),
            }),
        );

        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq!(
            *change_handler_log,
            vec![AutomapChange::Error(AutomapError::SocketReceiveError(
                AutomapErrorCause::SocketFailure
            ))]
        );
        TestLogHandler::new().exists_log_containing("ERROR: test: Remapping after IP change failed; Node is useless: SocketReceiveError(Unknown(\"Kind(ConnectionReset)\"))");
    }

    #[test]
    fn handle_announcement_rejects_unexpected_request() {
        init_test_logging();
        let router_address = SocketAddr::from_str("7.7.7.7:1234").unwrap();
        let mut packet = PmpPacket::default();
        packet.direction = Direction::Request;
        packet.opcode = Opcode::MapTcp;
        packet.opcode_data = Box::new(MapOpcodeData::default());
        let mut buffer = [0u8; 100];
        let buflen = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(100))
            .recv_from_result(Ok((buflen, router_address)), buffer[0..buflen].to_vec());
        let factories = Factories {
            socket_factory: Box::new(UdpSocketWrapperFactoryMock::new().make_result(Ok(socket))),
            free_port_factory: Box::new(FreePortFactoryMock::new().make_result(1234)),
        };
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_inner = change_handler_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_handler_log_inner.lock().unwrap().push(change));
        let logger = Logger::new("test");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_address.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            change_handler,
            unbounded().1,
        );
        subject.router_addr = router_address;
        subject.factories_arc = Arc::new(Mutex::new(factories));
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(MappingAdderMock::new()))); // no results
        subject.logger = logger;

        subject.handle_announcement(
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
            &Some(MappingConfig {
                hole_port: 2222,
                next_lifetime: Duration::from_secs(10),
                remap_interval: Duration::from_secs(0),
            }),
        );

        // No complaint from MappingAdderMock about not having a result for add_mapping; test passes
    }

    #[test]
    fn handle_announcement_rejects_temporarily_unsuccessful_result_code() {
        init_test_logging();
        let router_address = SocketAddr::from_str("7.7.7.7:1234").unwrap();
        let mut packet = PmpPacket::default();
        packet.direction = Direction::Response;
        packet.opcode = Opcode::MapTcp;
        packet.result_code_opt = Some(ResultCode::OutOfResources);
        packet.opcode_data = Box::new(MapOpcodeData::default());
        let mut buffer = [0u8; 100];
        let buflen = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(100))
            .recv_from_result(Ok((buflen, router_address)), buffer[0..buflen].to_vec());
        let factories = Factories {
            socket_factory: Box::new(UdpSocketWrapperFactoryMock::new().make_result(Ok(socket))),
            free_port_factory: Box::new(FreePortFactoryMock::new().make_result(1234)),
        };
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_inner = change_handler_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_handler_log_inner.lock().unwrap().push(change));
        let logger = Logger::new("test");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_address.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            change_handler,
            unbounded().1,
        );
        subject.router_addr = router_address;
        subject.factories_arc = Arc::new(Mutex::new(factories));
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(MappingAdderMock::new())));
        subject.logger = logger;

        subject.handle_announcement(
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
            &mut Some(MappingConfig {
                hole_port: 2222,
                next_lifetime: Duration::from_secs(10),
                remap_interval: Duration::from_secs(0),
            }),
        );

        let change_handler_log = change_handler_log_arc.lock().unwrap();
        let err_msg = "Remapping after IP change failed; Node is useless: OutOfResources";
        assert_eq!(
            *change_handler_log,
            vec![AutomapChange::Error(AutomapError::TemporaryMappingError(
                err_msg.to_string()
            ))]
        );
        TestLogHandler::new().exists_log_containing(&format!("ERROR: test: {}", err_msg));
    }

    #[test]
    fn handle_announcement_rejects_permanently_unsuccessful_result_code() {
        init_test_logging();
        let router_address = SocketAddr::from_str("7.7.7.7:1234").unwrap();
        let mut packet = PmpPacket::default();
        packet.direction = Direction::Response;
        packet.opcode = Opcode::MapTcp;
        packet.result_code_opt = Some(ResultCode::UnsupportedVersion);
        packet.opcode_data = Box::new(MapOpcodeData::default());
        let mut buffer = [0u8; 100];
        let buflen = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(100))
            .recv_from_result(Ok((buflen, router_address)), buffer[0..buflen].to_vec());
        let factories = Factories {
            socket_factory: Box::new(UdpSocketWrapperFactoryMock::new().make_result(Ok(socket))),
            free_port_factory: Box::new(FreePortFactoryMock::new().make_result(1234)),
        };
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_inner = change_handler_log_arc.clone();
        let change_handler: ChangeHandler =
            Box::new(move |change| change_handler_log_inner.lock().unwrap().push(change));
        let logger =
            Logger::new("handle_announcement_rejects_permanently_unsuccessful_result_code");
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(
            &transactor,
            router_address.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            change_handler,
            unbounded().1,
        );
        subject.router_addr = router_address;
        subject.factories_arc = Arc::new(Mutex::new(factories));
        subject.mapping_adder_arc = Arc::new(Mutex::new(Box::new(MappingAdderMock::new())));
        subject.logger = logger;

        subject.handle_announcement(
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
            &mut Some(MappingConfig {
                hole_port: 2222,
                next_lifetime: Duration::from_secs(10),
                remap_interval: Duration::from_secs(0),
            }),
        );

        let change_handler_log = change_handler_log_arc.lock().unwrap();
        let err_msg = "Remapping after IP change failed; Node is useless: UnsupportedVersion";
        assert_eq!(
            *change_handler_log,
            vec![AutomapChange::Error(AutomapError::PermanentMappingError(
                err_msg.to_string()
            ))]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: handle_announcement_rejects_permanently_unsuccessful_result_code: {}",
            err_msg
        ));
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_greater_than_one_second() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>> = Arc::new(Mutex::new(Box::new(
            MappingAdderMock::new()
                .add_mapping_params(&add_mapping_params_arc)
                .add_mapping_result(Err(AutomapError::Unknown)), // means smaller setup
        )));
        let mut transactor = PmpTransactor::new();
        transactor.mapping_adder_arc = mapping_adder_arc.clone();
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
            mapping_adder_arc.lock().unwrap().as_ref(),
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_millis(100900), // greater than one second
                remap_interval: Default::default(),
            },
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(add_mapping_params.remove(0).2.next_lifetime_secs(), 100); // rounds down to int seconds
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_less_than_one_second() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>> = Arc::new(Mutex::new(Box::new(
            MappingAdderMock::new()
                .add_mapping_params(&add_mapping_params_arc)
                .add_mapping_result(Err(AutomapError::Unknown)), // means smaller setup
        )));
        let mut transactor = PmpTransactor::new();
        transactor.mapping_adder_arc = mapping_adder_arc.clone();
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
            mapping_adder_arc.lock().unwrap().as_ref(),
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_millis(80), // less than one second
                remap_interval: Default::default(),
            },
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(add_mapping_params.remove(0).2.next_lifetime_secs(), 1); // rounds up to one second
    }

    #[test]
    fn remap_port_handles_temporary_mapping_failure() {
        let mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>> = Arc::new(Mutex::new(Box::new(
            MappingAdderMock::new().add_mapping_result(Err(AutomapError::TemporaryMappingError(
                "NetworkFailure".to_string(),
            ))),
        )));
        let mut transactor = PmpTransactor::new();
        transactor.mapping_adder_arc = mapping_adder_arc.clone();
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
            mapping_adder_arc.lock().unwrap().as_ref(),
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Default::default(),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::TemporaryMappingError(
                "NetworkFailure".to_string()
            ))
        );
    }

    #[test]
    fn remap_port_handles_permanent_mapping_failure() {
        let mapping_adder_arc: Arc<Mutex<Box<dyn MappingAdder>>> = Arc::new(Mutex::new(Box::new(
            MappingAdderMock::new().add_mapping_result(Err(AutomapError::PermanentMappingError(
                "MalformedRequest".to_string(),
            ))),
        )));
        let mut transactor = PmpTransactor::new();
        transactor.mapping_adder_arc = mapping_adder_arc.clone();
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            Box::new(UdpSocketWrapperMock::new()),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
            mapping_adder_arc.lock().unwrap().as_ref(),
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Default::default(),
                remap_interval: Default::default(),
            },
        );

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError(
                "MalformedRequest".to_string()
            ))
        );
    }

    fn make_subject(socket_factory: UdpSocketWrapperFactoryMock) -> PmpTransactor {
        let mut subject = PmpTransactor::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);
        factories.free_port_factory = Box::new(FreePortFactoryMock::new().make_result(5566));
        subject.factories_arc = Arc::new(Mutex::new(factories));
        subject
    }

    fn make_request(opcode: Opcode, opcode_data: Box<dyn PmpOpcodeData>) -> PmpPacket {
        PmpPacket {
            direction: Direction::Request,
            opcode,
            result_code_opt: None,
            opcode_data,
        }
    }

    fn make_get_request() -> Box<GetOpcodeData> {
        Box::new(GetOpcodeData {
            epoch_opt: None,
            external_ip_address_opt: None,
        })
    }

    fn make_map_request(port: u16, lifetime: u32) -> Box<MapOpcodeData> {
        Box::new(MapOpcodeData {
            epoch_opt: None,
            internal_port: port,
            external_port: port,
            lifetime,
        })
    }

    fn make_response(
        opcode: Opcode,
        result_code: ResultCode,
        opcode_data: Box<dyn PmpOpcodeData>,
    ) -> PmpPacket {
        PmpPacket {
            direction: Direction::Response,
            opcode,
            result_code_opt: Some(result_code),
            opcode_data,
        }
    }

    fn make_get_response(epoch_time: u32, external_ip_address: Ipv4Addr) -> Box<GetOpcodeData> {
        Box::new(GetOpcodeData {
            epoch_opt: Some(epoch_time),
            external_ip_address_opt: Some(external_ip_address),
        })
    }

    fn make_map_response(epoch_time: u32, port: u16, lifetime: u32) -> Box<MapOpcodeData> {
        Box::new(MapOpcodeData {
            epoch_opt: Some(epoch_time),
            internal_port: port,
            external_port: port,
            lifetime,
        })
    }
}
