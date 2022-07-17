// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::convert::TryFrom;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{unbounded, Receiver, Sender};

use masq_lib::logger::Logger;
use masq_lib::utils::AutomapProtocol;
use masq_lib::{debug, error, info, warning};

use crate::comm_layer::pcp_pmp_common::{find_routers, make_local_socket_address, FreePortFactory, FreePortFactoryReal, MappingConfig, UdpSocketWrapperFactoryReal, UdpSocketWrapperFactory, HOUSEKEEPING_THREAD_LOOP_DELAY_MILLIS, ROUTER_SERVER_PORT, PoliteUdpSocketWrapperFactory, PoliteUdpSocketWrapperFactoryReal, UdpSocketWrapper, NullUdpSocketWrapper};
use crate::comm_layer::{AutomapError, AutomapErrorCause, HousekeepingThreadCommand, MulticastInfo, Transactor};
use crate::control_layer::automap_control::{AutomapChange, ChangeHandler};
use crate::protocols::pmp::get_packet::GetOpcodeData;
use crate::protocols::pmp::map_packet::MapOpcodeData;
use crate::protocols::pmp::pmp_packet::{Opcode, PmpPacket, ResultCode};
use crate::protocols::utils::{Direction, Packet};

const PMP_READ_TIMEOUT_MS: u64 = 3000;

struct Factories {
    socket_factory: Box<dyn UdpSocketWrapperFactory>,
    polite_socket_factory: Box<dyn PoliteUdpSocketWrapperFactory>,
    free_port_factory: Box<dyn FreePortFactory>,
}

impl Default for Factories {
    fn default() -> Self {
        Self {
            socket_factory: Box::new(UdpSocketWrapperFactoryReal::new()),
            polite_socket_factory: Box::new (PoliteUdpSocketWrapperFactoryReal::new()),
            free_port_factory: Box::new(FreePortFactoryReal::new()),
        }
    }
}

pub struct PmpTransactorInner {
    mapping_adder: Box<dyn MappingAdder>,
    factories: Factories,
    socket_read_timeout: Duration,
    external_ip_addr_opt: Option<IpAddr>,
}

pub struct PmpTransactor {
    inner_arc: Arc<Mutex<PmpTransactorInner>>,
    router_port: u16,
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

    fn get_multicast_info(&self) -> MulticastInfo {
        MulticastInfo::default()
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
            &self.inner_arc.lock().expect("PmpTransactor is dead").factories,
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
        let inner = self.inner_arc.lock().expect ("Housekeeping thread is dead");
        inner
            .mapping_adder
            .add_mapping(
                &inner.factories,
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
        _router_multicast_info: &MulticastInfo,
    ) -> Result<Sender<HousekeepingThreadCommand>, AutomapError> {
        debug!(
            self.logger,
            "Starting housekeeping thread for router at {}", router_ip
        );
        if let Some(_housekeeper_commander) = &self.housekeeper_commander_opt {
            return Err(AutomapError::HousekeeperAlreadyRunning);
        }
        let (tx, rx) = unbounded();
        self.housekeeper_commander_opt = Some(tx.clone());
        let thread_guts = ThreadGuts::new(self, router_ip, MulticastInfo::for_test(10), change_handler, rx);
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
            inner_arc: Arc::new (Mutex::new (PmpTransactorInner {
                mapping_adder: Box::new (MappingAdderReal::default()),
                factories: Factories::default(),
                socket_read_timeout: Duration::from_millis(PMP_READ_TIMEOUT_MS),
                external_ip_addr_opt: None,
            })),
            router_port: ROUTER_SERVER_PORT,
            housekeeper_commander_opt: None,
            read_timeout_millis: HOUSEKEEPING_THREAD_LOOP_DELAY_MILLIS,
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
        factories: &Factories,
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
    housekeeper_commander: Receiver<HousekeepingThreadCommand>,
    inner_arc: Arc<Mutex<PmpTransactorInner>>,
    router_multicast_info: MulticastInfo,
    router_addr: SocketAddr,
    change_handler: ChangeHandler,
    read_timeout_millis: u64,
    logger: Logger,
}

impl ThreadGuts {
    pub fn new(
        transactor: &PmpTransactor,
        router_ip: IpAddr,
        router_multicast_info: MulticastInfo,
        change_handler: ChangeHandler,
        housekeeper_commander: Receiver<HousekeepingThreadCommand>,
    ) -> Self {
        Self {
            housekeeper_commander,
            inner_arc: transactor.inner_arc.clone(),
            router_multicast_info,
            router_addr: SocketAddr::new(router_ip, transactor.router_port),
            change_handler,
            read_timeout_millis: transactor.read_timeout_millis,
            logger: transactor.logger.clone(),
        }
    }

    pub fn go(self) -> JoinHandle<ChangeHandler> {
        thread::spawn(move || self.thread_guts())
    }

    fn thread_guts(mut self) -> ChangeHandler {
        let unsolicited_socket = self.make_unsolicited_socket();
        let mut mapping_config_opt = None;
        let mut last_remapped = Instant::now();
        while self.thread_guts_iteration(unsolicited_socket.as_ref(), &mut mapping_config_opt, &mut last_remapped) {}
        self.change_handler
    }

    fn thread_guts_iteration(
        &mut self,
        unsolicited_socket: &dyn UdpSocketWrapper,
        mapping_config_opt: &mut Option<MappingConfig>,
        last_remapped: &mut Instant,
    ) -> bool {
        if let Some(mapping_config) = mapping_config_opt {
            self.maybe_remap(mapping_config, last_remapped);
        }
        match self.housekeeper_commander.try_recv() {
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
        thread::sleep(Duration::from_millis(self.read_timeout_millis)); // used to be a read timeout
        true
    }

    fn maybe_remap(&self, mapping_config: &mut MappingConfig, last_remapped: &mut Instant) {
        let since_last_remapped = last_remapped.elapsed();
        if since_last_remapped.gt(&mapping_config.remap_interval) {
            if let Err(e) = self.remap_port(
                mapping_config
            ) {
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

    fn remap_port(
        &self,
        mapping_config: &mut MappingConfig,
    ) -> Result<u32, AutomapError> {
        info!(&self.logger, "Remapping port {}", mapping_config.hole_port);
        if mapping_config.next_lifetime.as_millis() < 1000 {
            mapping_config.next_lifetime = Duration::from_millis(1000);
        }
        let inner = self.inner_arc.lock().expect("MappingAdder is dead");
        inner.mapping_adder.add_mapping(&inner.factories, self.router_addr, mapping_config)
    }

    fn make_unsolicited_socket(&self) -> Box<dyn UdpSocketWrapper> {
        let unsolicited_socket = match self.inner_arc
            .lock()
            .expect ("PmpTransactor is dead")
            .factories
            .polite_socket_factory
            .make (&self.router_multicast_info) {
            Ok (socket) => {
                socket
            },
            Err (e) => {
                (self.change_handler) (AutomapChange::Error(AutomapError::MulticastBindingError(
                    format! ("{:?}", e),
                    self.router_multicast_info.clone(),
                )));
                error! (self.logger, "Could not open unsolicited multicast PMP router socket; ISP IP changes will not be processed: {:?}", e);
                Box::new (NullUdpSocketWrapper::new())
            }
        };
        unsolicited_socket.set_read_timeout(Some (Duration::from_millis (self.read_timeout_millis))).expect("Couldn't set read timeout for announce socket");
        unsolicited_socket.set_nonblocking(true).expect ("Couldn't set announce socket to nonblocking");
        unsolicited_socket
    }

    fn check_unsolicited_socket (
        &self,
        unsolicited_socket: &dyn UdpSocketWrapper,
        buffer: &mut [u8],
        mapping_config_opt: &mut Option<MappingConfig>,
        last_remapped: &mut Instant,
    ) {
        match unsolicited_socket.recv(&mut buffer[..]) {
            Ok (len) => {
                match PmpPacket::try_from (&buffer[0..len]) {
                    Ok (packet) if packet.opcode == Opcode::MapUdp => {
                        let map_opcode_data = packet.opcode_data.as_any().downcast_ref::<MapOpcodeData>()
                            .expect("Marshalling MapUdp packet produced other than MapOpcodeData");
                        Self::process_unsolicited_map(&self.inner_arc, map_opcode_data,
                            self.router_addr, mapping_config_opt,
                            last_remapped, &self.change_handler, &self.logger)
                    },
                    Ok (packet) => {
                        warning! (&self.logger, "Discarding unsolicited {:?} packet from router", packet.opcode);
                    },
                    Err (e) => {
                        error!(&self.logger, "Could not parse unsolicited PCP packet from router: {:?}", e)
                    },
                }
            },
            Err (e) if (e.kind() == ErrorKind::TimedOut) || (e.kind() == ErrorKind::WouldBlock) => (),
            Err (e) => {
                error!(&self.logger, "Could not read from unsolicited router socket: {:?}", e)
            }
        };
    }

    fn process_unsolicited_map(
        inner_arc: &Arc<Mutex<PmpTransactorInner>>,
        map_opcode_data: &MapOpcodeData,
        router_server_addr: SocketAddr,
        mut mapping_config_opt: &mut Option<MappingConfig>,
        mut last_remapped: &mut Instant,
        change_handler: &ChangeHandler,
        logger: &Logger
    ) {
        let mut inner = inner_arc.lock().expect ("PmpTransactor is dead");
        match inner.factories.socket_factory.make(router_server_addr) {
            Ok(socket) => {
                if let Some (get_opcode_data) = Self::execute_get_transaction(socket,
                    &inner, router_server_addr, change_handler, logger) {
                    Self::process_get_response(
                        &map_opcode_data,
                        &get_opcode_data,
                        &mut inner,
                        &mut mapping_config_opt,
                        &mut last_remapped,
                        change_handler,
                        logger
                    );
                }
            },
            Err(e) => {
                change_handler(AutomapChange::Error(AutomapError::SocketBindingError(
                    format!("Can't communicate with router, manual portmapping maybe required: {:?}", e),
                    router_server_addr,
                )));
                error! (logger, "Failed to contact router, manual portmapping may be required: {:?}", e);
            },
        }
    }

    fn execute_get_transaction(
        socket: Box<dyn UdpSocketWrapper>,
        inner: &PmpTransactorInner,
        router_server_addr: SocketAddr,
        change_handler: &ChangeHandler,
        logger: &Logger
    ) -> Option<GetOpcodeData> {
        socket.set_read_timeout(Some(inner.socket_read_timeout)).expect("Couldn't set read timeout on socket");
        let get_request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData { epoch_opt: None, external_ip_address_opt: None })
        };
        let mut get_request_bytes = [0u8; 64];
        let get_request_len = get_request.marshal(&mut get_request_bytes).expect("Bad message format");
        match socket.send_to(&mut get_request_bytes[0..get_request_len], router_server_addr) {
            Ok(_) => {
                Self::receive_get_response(socket, router_server_addr, logger)
            },
            Err(e) => {
                change_handler (AutomapChange::Error(AutomapError::SocketSendError(AutomapErrorCause::SocketFailure)));
                error! (logger, "Failed to send GET request to router, manual portmapping may be required: {:?}", e);
                None
            },
        }
    }

    fn receive_get_response(
        socket: Box<dyn UdpSocketWrapper>,
        router_server_addr: SocketAddr,
        logger: &Logger
    ) -> Option<GetOpcodeData> {
        let mut get_response_bytes = [0u8; 64];
        match socket.recv_from(&mut get_response_bytes[..]) {
            Ok((get_response_len, addr)) if addr == router_server_addr => {
                match PmpPacket::try_from(&get_response_bytes[0..get_response_len]) {
                    Ok(get_response) => {
                        match get_response.opcode_data.as_any().downcast_ref::<GetOpcodeData>() {
                            Some(opcode_data) => {
                                Some (opcode_data.clone())
                            }
                            None => todo!("Downcast error"),
                        }
                    },
                    Err(e) => todo!("{:?}", e),
                }
            },
            Ok(_) => todo!("Not for us"),
            Err(e) => todo!("{:?}", e),
        }
    }

    fn process_get_response(
        map_opcode_data: &MapOpcodeData,
        get_opcode_data: &GetOpcodeData,
        inner: &mut MutexGuard<PmpTransactorInner>,
        mapping_config_opt: &mut Option<MappingConfig>,
        last_remapped: &mut Instant,
        change_handler: &ChangeHandler,
        logger: &Logger
    ) {
        if let Some(external_ip_address) = get_opcode_data.external_ip_address_opt {
            // let changed = {
            //     let mut inner = inner_arc.lock().expect("PmpTransactor died");
            //     let changed = inner.external_ip_addr_opt != Some (opcode_data.external_ip_address);
            //     inner.external_ip_addr_opt = Some(opcode_data.external_ip_address);
            //     changed
            // };
            // TODO: Drive me back in
            // if changed {
            if let Some(mapping_config) = mapping_config_opt.as_mut() {
                mapping_config.next_lifetime = Duration::from_secs(map_opcode_data.lifetime as u64);
                mapping_config.remap_interval = Duration::from_secs((map_opcode_data.lifetime / 2) as u64);
            }
            *last_remapped = Instant::now();
            inner.external_ip_addr_opt = Some(IpAddr::V4(external_ip_address));
            info!(logger, "Received PMP MAP notification that ISP changed IP address to {}", external_ip_address);
            change_handler(AutomapChange::NewIp(IpAddr::V4(external_ip_address)));
            // }
            // else {
            //     info!(logger, "Received PMP MAP notification that ISP changed IP address; but address is unchanged from {}; ignoring", opcode_data.external_ip_address);
            // }
        } else {
            todo!("Bad response packet")
        }
    }
}

trait MappingAdder: Send {
    fn add_mapping(
        &self,
        factories: &Factories,
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
        factories: &Factories,
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
            factories,
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
    use std::cell::RefCell;
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::ops::Sub;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::{io, thread};

    use lazy_static::lazy_static;

    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::{AutomapProtocol, find_free_port, localhost};

    use crate::comm_layer::pcp_pmp_common::MappingConfig;
    use crate::comm_layer::{AutomapErrorCause, MulticastInfo};
    use crate::control_layer::automap_control::AutomapChange;
    use crate::mocks::{FreePortFactoryMock, PoliteUdpSocketWrapperFactoryMock, UdpSocketWrapperFactoryMock, UdpSocketWrapperMock};
    use crate::protocols::pmp::get_packet::GetOpcodeData;
    use crate::protocols::pmp::map_packet::MapOpcodeData;
    use crate::protocols::pmp::pmp_packet::{Opcode, PmpOpcodeData, PmpPacket, ResultCode};
    use crate::protocols::utils::{Direction, Packet, ParseError, UnrecognizedData};

    use super::*;

    lazy_static! {
        static ref ROUTER_ADDR: SocketAddr = SocketAddr::from_str("1.2.3.4:5351").unwrap();
        static ref PUBLIC_IP: IpAddr = IpAddr::from_str("2.3.4.5").unwrap();
    }

    struct MappingAdderMock {
        add_mapping_params: Arc<Mutex<Vec<(SocketAddr, MappingConfig)>>>,
        add_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
    }

    impl MappingAdder for MappingAdderMock {
        fn add_mapping(
            &self,
            _: &Factories,
            router_addr: SocketAddr,
            mapping_config: &mut MappingConfig,
        ) -> Result<u32, AutomapError> {
            let result = self.add_mapping_results.borrow_mut().remove(0);
            if let Ok(remap_interval) = &result {
                mapping_config.remap_interval = Duration::from_secs(*remap_interval as u64);
            }
            // We can't find any workable way to record the `factories` parameter.
            self.add_mapping_params.lock().unwrap().push((
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
            params: &Arc<Mutex<Vec<(SocketAddr, MappingConfig)>>>,
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
        let subject = make_socket_subject(socket_factory);

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
        let subject = make_socket_subject(socket_factory);

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
        let subject = make_socket_subject(socket_factory);

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
            .recv_from_result(Ok((0, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = PmpTransactor::default();
        subject.inner_arc.lock().unwrap().factories.socket_factory = Box::new(socket_factory);

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
                &factories,
                SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
            &factories,
            SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
            &factories,
            SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
            .recv_from_result(Ok((0, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))), vec![]);
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &factories,
            SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
                Ok((len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &factories,
            SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
                Ok((len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = MappingAdderReal::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);

        let result = subject.add_mapping(
            &factories,
            SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
                Ok((len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
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
            &factories,
            SocketAddr::new(router_ip, ROUTER_SERVER_PORT),
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
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_socket_subject(socket_factory);

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
                SocketAddr::new(router_ip, ROUTER_SERVER_PORT)
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
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_socket_subject(socket_factory);

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
        let main_socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(request_len))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(main_socket));
        let mut subject = make_socket_subject(socket_factory);
        subject
            .start_housekeeping_thread(Box::new(|_| ()), router_ip, &MulticastInfo::for_test(8))
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
                SocketAddr::new(router_ip, ROUTER_SERVER_PORT)
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
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_socket_subject(socket_factory);

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
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(socket));
        let subject = make_socket_subject(socket_factory);

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
        let main_socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params(&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(request_len))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((response_len, SocketAddr::new(router_ip, ROUTER_SERVER_PORT))),
                response_buffer[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketWrapperFactoryMock::new().make_result(Ok(main_socket));
        let mut subject = make_socket_subject(socket_factory);
        subject
            .start_housekeeping_thread(
                Box::new(|_| ()),
                router_ip,
                &MulticastInfo::for_test(9)
            )
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
                SocketAddr::new(router_ip, ROUTER_SERVER_PORT)
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()])
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
        let mut subject = make_mapping_adder_subject(mapping_adder);
        let _ =
            subject.start_housekeeping_thread(change_handler, IpAddr::from_str("1.2.3.4").unwrap(), &MulticastInfo::for_test(10));

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
        drop(rx);

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
    fn make_unsolicited_socket_handles_error() {
        init_test_logging();
        let polite_socket_factory = PoliteUdpSocketWrapperFactoryMock::new()
            .make_result (Err (io::Error::from (ErrorKind::ConnectionRefused)));
        let factories = Factories {
            socket_factory: Box::new(UdpSocketWrapperFactoryMock::new()), // not used
            polite_socket_factory: Box::new(polite_socket_factory),
            free_port_factory: Box::new(FreePortFactoryMock::new()) // not used
        };
        let inner = PmpTransactorInner {
            mapping_adder: Box::new(MappingAdderMock::new()),
            factories,
            socket_read_timeout: Duration::from_millis (1000),
            external_ip_addr_opt: None,
        };
        let inner_arc = Arc::new(Mutex::new(inner));
        let mut transactor = PmpTransactor::new();
        transactor.inner_arc = inner_arc;
        let router_multicast_info = MulticastInfo::new (IpAddr::from_str("1.2.3.4").unwrap(), 5, 8888);
        // let read_timeout_millis = 1000;
        let received_error_arc: Arc<Mutex<Vec<AutomapError>>> = Arc::new (Mutex::new (vec![]));
        let inner_received_error_arc = received_error_arc.clone();
        let change_handler: ChangeHandler = Box::new (move |msg| {
            match msg {
                AutomapChange::Error(err) => inner_received_error_arc.lock().unwrap().push (err),
                _ => (),
            };
        });
        let logger = Logger::new ("make_unsolicited_socket_handles_error");
        let mut subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            router_multicast_info.clone(),
            change_handler,
            unbounded().1
        );
        subject.logger = logger;

        let result = subject.make_unsolicited_socket ();

        assert_eq! (result.recv (&mut []).err().unwrap().kind(), ErrorKind::TimedOut);
        assert_eq! (result.send_to (&[1, 2, 3], SocketAddr::new (localhost(), find_free_port())).unwrap(), 3);
        let received_errors = received_error_arc.lock().unwrap();
        assert_eq! (
            *received_errors,
            vec![AutomapError::MulticastBindingError(
                "Kind(ConnectionRefused)".to_string(),
                router_multicast_info
            )]
        );
        TestLogHandler::new().exists_log_containing("ERROR: make_unsolicited_socket_handles_error: Could not open unsolicited multicast PMP router socket; ISP IP changes will not be processed: Kind(ConnectionRefused)");
    }

    #[test]
    fn thread_guts_does_not_remap_if_interval_does_not_run_out() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let mapping_adder = MappingAdderMock::new(); // no results specified
        let mapping_config = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_secs(20),
            remap_interval: Duration::from_secs(10),
        };
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(&transactor, ROUTER_ADDR.ip(), MulticastInfo::for_test(20), Box::new(move |_| {}), rx);
        subject.inner_arc.lock().unwrap().mapping_adder = Box::new (mapping_adder);
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
        let mapping_adder = Box::new(MappingAdderMock::new()
            .add_mapping_params(&add_mapping_params_arc)
            .add_mapping_result(Ok(300)),
        );
        let free_port_factory = FreePortFactoryMock::new().make_result(5555);
        let mut factories = Factories::default();
        factories.free_port_factory = Box::new(free_port_factory);
        let mapping_config = MappingConfig {
            hole_port: 6689,
            next_lifetime: Duration::from_secs(1000),
            remap_interval: Duration::from_millis(80),
        };
        let transactor = PmpTransactor::new();
        let mut subject = ThreadGuts::new(&transactor, ROUTER_ADDR.ip(), MulticastInfo::for_test(30), Box::new(move |_| {}), rx);
        {
            let mut inner = transactor.inner_arc.lock().unwrap();
            inner.mapping_adder = mapping_adder;
            inner.factories = factories;
        }
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
        let (router_addr, mapping_config) = add_mapping_params_arc.lock().unwrap().remove(0);
        assert_eq!(router_addr, *ROUTER_ADDR);
        assert_eq!(
            mapping_config,
            MappingConfig {
                hole_port: 6689,
                next_lifetime: Duration::from_secs(1000),
                remap_interval: Duration::from_secs(300)
            }
        );
        TestLogHandler::new().exists_log_containing("INFO: timed_remap_test: Remapping port 6689");
    }

    #[test]
    fn check_unsolicited_socket_handles_unsolicited_map_packet() {
        init_test_logging();
        let old_ip_addr = IpAddr::from_str("2.2.2.2").unwrap();
        let new_ip_addr = IpAddr::from_str ("4.3.2.1").unwrap();
        let mut map_response_buffer = [0u8; 64];
        let map_opcode_data = MapOpcodeData {
            epoch_opt: None,
            internal_port: 1234,
            external_port: 1234,
            lifetime: 600
        };
        let map_response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::MapUdp,
            result_code_opt: Some (ResultCode::Success),
            opcode_data: Box::new(map_opcode_data),
        };
        let map_response_len = map_response.marshal (&mut map_response_buffer[..]).unwrap();
        let mut get_request_buffer = [0u8; 64];
        let get_request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: None
            }),
        };
        let get_request_len = get_request.marshal(&mut get_request_buffer[..]).unwrap();
        let mut get_response_buffer = [0u8; 64];
        let get_response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::Get,
            result_code_opt: Some(ResultCode::Success),
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: Some (Ipv4Addr::from_str (&new_ip_addr.to_string()).unwrap()),
            }),
        };
        let get_response_len = get_response.marshal(&mut get_response_buffer[..]).unwrap();
        let router_multicast_info = MulticastInfo::for_test(80);
        let unsolicited_socket = UdpSocketWrapperMock::new()
            .recv_result (Ok(map_response_len), map_response_buffer[0..map_response_len].to_vec());
        let router_server_addr = SocketAddr::from_str ("1.2.3.4:5000").unwrap();
        let mut mapping_config_opt = Some (MappingConfig {
            hole_port: 1234,
            next_lifetime: Duration::from_secs (600),
            remap_interval: Duration::from_secs (300),
        });
        let mut last_remapped = Instant::now().sub (Duration::from_secs (3600));
        let received_new_ip: Arc<Mutex<Option<IpAddr>>> = Arc::new (Mutex::new (None));
        let inner_received_new_ip = received_new_ip.clone();
        let change_handler: ChangeHandler = Box::new (move |msg| {
            match msg {
                AutomapChange::NewIp(new_ip) => inner_received_new_ip.lock().unwrap().replace (new_ip),
                _ => None,
            };
        });
        let logger = Logger::new ("check_unsolicited_socket_handles_unsolicited_map_packet");
        let set_read_timeout_params_arc = Arc::new (Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_params (&set_read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(get_request_len))
            .recv_from_result(Ok((get_response_len, router_server_addr)), get_response_buffer.to_vec());
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_result (Ok (socket));
        let mut factories = Factories::default();
        factories.socket_factory = Box::new (socket_factory);
        let inner = PmpTransactorInner {
            mapping_adder: Box::new(MappingAdderReal::default()),
            factories,
            socket_read_timeout: Duration::from_millis(15),
            external_ip_addr_opt: Some (old_ip_addr),
        };
        let inner_arc = Arc::new (Mutex::new (inner));
        let assertable_inner_arc = inner_arc.clone();
        let mut transactor = PmpTransactor::new();
        transactor.inner_arc = inner_arc;
        transactor.router_port = router_server_addr.port();
        transactor.read_timeout_millis = 10;
        transactor.logger = logger;
        let subject = ThreadGuts::new (
            &transactor,
            router_server_addr.ip(),
            router_multicast_info,
            change_handler,
            unbounded().1,
        );
        let before = Instant::now();

        subject.check_unsolicited_socket(
            &unsolicited_socket,
            &mut map_response_buffer[..],
            &mut mapping_config_opt,
            &mut last_remapped,
        );

        let after = Instant::now();
        let change = received_new_ip.lock().unwrap().take().unwrap();
        assert_eq! (change, new_ip_addr);
        assert_eq! (mapping_config_opt, Some (MappingConfig {
            hole_port: 1234,
            next_lifetime: Duration::from_secs (600),
            remap_interval: Duration::from_secs (300)
        }));
        assert! (last_remapped.ge (&before));
        assert! (last_remapped.le (&after));
        let assertable_inner = assertable_inner_arc.lock().unwrap();
        assert_eq! (assertable_inner.external_ip_addr_opt, Some (new_ip_addr));
        TestLogHandler::new().exists_log_containing("INFO: check_unsolicited_socket_handles_unsolicited_map_packet: Received PMP MAP notification that ISP changed IP address to 4.3.2.1");
    }

    #[test]
    fn check_unsolicited_socket_handles_receive_error() {
        init_test_logging();
        let unsolicited_socket = UdpSocketWrapperMock::new()
            .recv_result (Err (io::Error::from (ErrorKind::BrokenPipe)), vec![]);
        let (change_handler, received_error_arc) = make_change_handler_expecting_error();
        let mut buffer = [0u8; 0];
        let mut mapping_config_opt = None;
        let subject = ThreadGuts::new (
            &PmpTransactor::new(),
            IpAddr::from_str("1.1.1.1").unwrap(),
            MulticastInfo::for_test(20),
            change_handler,
            unbounded().1
        );

        subject.check_unsolicited_socket(&unsolicited_socket, &mut buffer[..],
            &mut mapping_config_opt, &mut Instant::now());

        let received_error = received_error_arc.lock().unwrap();
        assert_eq! (*received_error, None);
        TestLogHandler::new().exists_log_containing("ERROR: PmpTransactor: Could not read from unsolicited router socket: Kind(BrokenPipe)");
    }

    #[test]
    fn check_unsolicited_socket_handles_unexpected_packet_type() {
        init_test_logging();
        let get_packet = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData { epoch_opt: None, external_ip_address_opt: None })
        };
        let mut get_packet_bytes = [0u8; 64];
        let get_packet_len = get_packet.marshal (&mut get_packet_bytes[..]).unwrap();
        let unsolicited_socket = UdpSocketWrapperMock::new()
            .recv_result (Ok(get_packet_len), get_packet_bytes[0..get_packet_len].to_vec());
        let (change_handler, received_error_arc) = make_change_handler_expecting_error();
        let mut buffer = [0u8; 64];
        let mut mapping_config_opt = None;
        let subject = ThreadGuts::new (
            &PmpTransactor::new(),
            IpAddr::from_str("1.1.1.1").unwrap(),
            MulticastInfo::for_test(20),
            change_handler,
            unbounded().1
        );

        subject.check_unsolicited_socket(&unsolicited_socket, &mut buffer[..],
            &mut mapping_config_opt, &mut Instant::now());

        let received_error = received_error_arc.lock().unwrap();
        assert_eq! (*received_error, None);
        TestLogHandler::new().exists_log_containing("WARN: PmpTransactor: Discarding unsolicited Get packet from router");
    }

    #[test]
    fn check_unsolicited_socket_handles_invalid_packet() {
        init_test_logging();
        let packet_bytes = [0xFFu8];
        let packet_len = packet_bytes.len();
        let unsolicited_socket = UdpSocketWrapperMock::new()
            .recv_result (Ok(packet_len), packet_bytes[0..packet_len].to_vec());
        let (change_handler, received_error_arc) = make_change_handler_expecting_error();
        let mut buffer = [0u8; 64];
        let mut mapping_config_opt = None;
        let subject = ThreadGuts::new (
            &PmpTransactor::new(),
            IpAddr::from_str("1.1.1.1").unwrap(),
            MulticastInfo::for_test(20),
            change_handler,
            unbounded().1
        );

        subject.check_unsolicited_socket(&unsolicited_socket, &mut buffer[..],
            &mut mapping_config_opt, &mut Instant::now());

        let received_error = received_error_arc.lock().unwrap();
        assert_eq! (*received_error, None);
        TestLogHandler::new().exists_log_containing("ERROR: PmpTransactor: Could not parse unsolicited PCP packet from router: ShortBuffer");
    }

    #[test]
    fn process_unsolicited_map_handles_factory_failure() {
        init_test_logging();
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_result (Err (Error::from (ErrorKind::ConnectionRefused)));
        let mut factories = Factories::default();
        factories.socket_factory = Box::new (socket_factory);
        let inner = PmpTransactorInner {
            mapping_adder: Box::new(MappingAdderMock::new()), // irrelevant
            factories,
            socket_read_timeout: Duration::default(), // irrelevant
            external_ip_addr_opt: None // irrelevant
        };
        let inner_arc = Arc::new(Mutex::new (inner));
        let router_server_addr = SocketAddr::from_str("1.2.3.4:5000").unwrap();
        let mut mapping_config_opt = None;
        let mut last_remapped = Instant::now();
        let (change_handler, received_error_arc) = make_change_handler_expecting_error();
        let logger = Logger::new ("process_unsolicited_map_handles_factory_failure");

        ThreadGuts::process_unsolicited_map(
            &inner_arc,
            &MapOpcodeData::default(), // irrelevant
            router_server_addr,
            &mut mapping_config_opt, // irrelevant
            &mut last_remapped, // irrelevant
            &change_handler,  // irrelevant
            &logger,
        );

        let received_error = received_error_arc.lock().unwrap();
        assert_eq! (*received_error, Some (AutomapError::SocketBindingError("Can't communicate with router, manual portmapping maybe required: Kind(ConnectionRefused)".to_string(),
            router_server_addr)));
        TestLogHandler::new().exists_log_containing(
            "ERROR: process_unsolicited_map_handles_factory_failure: Failed to contact router, manual portmapping may be required: Kind(ConnectionRefused)"
        );
    }

    #[test]
    fn execute_get_transaction_handles_send_error() {
        init_test_logging();
        let socket = UdpSocketWrapperMock::new()
            .set_read_timeout_result (Ok(()))
            .send_to_result (Err (io::Error::from (ErrorKind::BrokenPipe)));
        let inner = PmpTransactorInner {
            mapping_adder: Box::new(MappingAdderMock::new()), // irrelevant
            factories: Factories::default(), // irrelevant
            socket_read_timeout: Duration::default(), // irrelevant
            external_ip_addr_opt: None // irrelevant
        };
        let router_server_addr = SocketAddr::from_str ("1.2.3.4:5000").unwrap();
        let (change_handler, received_error_arc) = make_change_handler_expecting_error();
        let logger = Logger::new ("execute_get_transaction_handles_send_error");

        let result = ThreadGuts::execute_get_transaction (
            Box::new (socket),
            &inner, // irrelevant
            router_server_addr, // irrelevant
            &change_handler,
            &logger,
        );

        assert_eq! (result, None);
        let received_error = received_error_arc.lock().unwrap();
        assert_eq! (*received_error, Some (AutomapError::SocketSendError(AutomapErrorCause::SocketFailure)));
        TestLogHandler::new().exists_log_containing("ERROR: execute_get_transaction_handles_send_error: Failed to send GET request to router, manual portmapping may be required: Kind(BrokenPipe)");
    }

    #[test]
    fn receive_get_response_handles_response_thats_not_for_us() {
        init_test_logging();
        let router_server_addr = SocketAddr::from_str ("1.2.3.4:5000").unwrap();
        let other_addr = SocketAddr::from_str ("5.4.3.2:1000").unwrap();
        let get_opcode_data = GetOpcodeData {
            epoch_opt: Some (1234),
            external_ip_address_opt: Some (Ipv4Addr::from_str ("5.5.5.5").unwrap()),
        };
        let get_response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::Get,
            result_code_opt: Some (ResultCode::Success),
            opcode_data: Box::new(get_opcode_data.clone())
        };
        let mut get_response_bytes = [0u8; 64];
        let get_response_len = get_response.marshal (&mut get_response_bytes[..]).unwrap();
        let socket = UdpSocketWrapperMock::new()
            .recv_from_result (Ok ((0, other_addr)), get_response_bytes[0..get_response_len].to_vec());
        let logger = Logger::new ("receive_get_response_handles_response_thats_not_for_us");

        let result = ThreadGuts::receive_get_response(
            Box::new (socket),
            router_server_addr,
            &logger,
        );

        assert_eq! (result, Some (get_opcode_data));
        TestLogHandler::new().exists_log_containing("WARN: receive_get_response_handles_response_thats_not_for_us: ");
    }

    #[test]
    fn maybe_remap_handles_remapping_error() {
        init_test_logging();
        let mapping_adder = MappingAdderMock::new()
                .add_mapping_result(Err(AutomapError::ProtocolError("Booga".to_string())));
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
        transactor.inner_arc.lock().unwrap().mapping_adder = Box::new (mapping_adder);
        let mut subject =
            ThreadGuts::new(&transactor, router_addr.ip(), MulticastInfo::for_test(50), change_handler, unbounded().1);
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
    fn remap_port_correctly_converts_lifetime_greater_than_one_second() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder = MappingAdderMock::new()
            .add_mapping_params(&add_mapping_params_arc)
            .add_mapping_result(Err(AutomapError::Unknown)); // means smaller setup;
        let transactor = make_mapping_adder_subject(mapping_adder);
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            MulticastInfo::for_test(60),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_millis(100900), // greater than one second
                remap_interval: Default::default(),
            },
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(add_mapping_params.remove(0).1.next_lifetime_secs(), 100); // rounds down to int seconds
    }

    #[test]
    fn remap_port_correctly_converts_lifetime_less_than_one_second() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mapping_adder = MappingAdderMock::new()
                .add_mapping_params(&add_mapping_params_arc)
                .add_mapping_result(Err(AutomapError::Unknown));
        let transactor = make_mapping_adder_subject(mapping_adder);
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            MulticastInfo::for_test(70),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
            &mut MappingConfig {
                hole_port: 0,
                next_lifetime: Duration::from_millis(80), // less than one second
                remap_interval: Default::default(),
            },
        );

        assert_eq!(result, Err(AutomapError::Unknown));
        let mut add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(add_mapping_params.remove(0).1.next_lifetime_secs(), 1); // rounds up to one second
    }

    #[test]
    fn remap_port_handles_temporary_mapping_failure() {
        let transactor = make_mapping_adder_subject(
            MappingAdderMock::new().add_mapping_result(Err(AutomapError::TemporaryMappingError(
                "NetworkFailure".to_string()
            )))
        );
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            MulticastInfo::for_test(80),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
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
        let inner_arc = Arc::new (Mutex::new (PmpTransactorInner {
            mapping_adder: Box::new(
                MappingAdderMock::new().add_mapping_result(Err(AutomapError::PermanentMappingError(
                    "MalformedRequest".to_string(),
                )))
            ),
            factories: Factories::default(),
            socket_read_timeout: Duration::from_millis(100),
            external_ip_addr_opt: None,
        }));
        let mut transactor = PmpTransactor::new();
        transactor.inner_arc = inner_arc;
        let subject = ThreadGuts::new(
            &transactor,
            ROUTER_ADDR.ip(),
            MulticastInfo::for_test(90),
            Box::new(|_| ()),
            unbounded().1,
        );

        let result = subject.remap_port(
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

    fn make_socket_subject(socket_factory: UdpSocketWrapperFactoryMock) -> PmpTransactor {
        let subject = PmpTransactor::default();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(socket_factory);
        factories.free_port_factory = Box::new(FreePortFactoryMock::new().make_result(5566));
        subject.inner_arc.lock().unwrap().factories = factories;
        subject
    }

    fn make_mapping_adder_subject(mapping_adder: MappingAdderMock) -> PmpTransactor {
        let inner_arc = Arc::new (Mutex::new (PmpTransactorInner {
            mapping_adder: Box::new (mapping_adder),
            factories: Factories::default(),
            socket_read_timeout: Duration::from_millis (100),
            external_ip_addr_opt: None,
        }));
        let mut transactor = PmpTransactor::new();
        transactor.inner_arc = inner_arc;
        transactor
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

    fn make_change_handler_expecting_error() -> (ChangeHandler, Arc<Mutex<Option<AutomapError>>>) {
        let received_error_arc: Arc<Mutex<Option<AutomapError>>> = Arc::new (Mutex::new (None));
        let inner_received_error = received_error_arc.clone();
        let change_handler: ChangeHandler = Box::new (move |msg| {
            match msg {
                AutomapChange::Error(error) => inner_received_error.lock().unwrap().replace (error),
                _ => None,
            };
        });
        (change_handler, received_error_arc)
    }
}
