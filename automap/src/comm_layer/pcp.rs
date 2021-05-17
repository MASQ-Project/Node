// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{
    find_routers, make_local_socket_address, ChangeHandlerConfig, FreePortFactory,
    FreePortFactoryReal, UdpSocketFactory, UdpSocketFactoryReal, UdpSocketWrapper,
    CHANGE_HANDLER_PORT, ROUTER_PORT,
};
use crate::comm_layer::{
    AutomapError, AutomapErrorCause, LocalIpFinder, LocalIpFinderReal, Transactor,
};
use crate::control_layer::automap_control::{AutomapChange, ChangeHandler};
use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
use crate::protocols::pcp::pcp_packet::{Opcode, PcpPacket, ResultCode};
use crate::protocols::utils::{Direction, Packet};
use crossbeam_channel::{unbounded, Receiver, Sender};
use masq_lib::error;
use masq_lib::logger::Logger;
use masq_lib::utils::AutomapProtocol;
use pretty_hex::PrettyHex;
use rand::RngCore;
use std::any::Any;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
    socket_factory: Box<dyn UdpSocketFactory>,
    local_ip_finder: Box<dyn LocalIpFinder>,
    mapping_nonce_factory: Box<dyn MappingNonceFactory>,
    free_port_factory: Box<dyn FreePortFactory>,
}

impl Default for Factories {
    fn default() -> Self {
        Self {
            socket_factory: Box::new(UdpSocketFactoryReal::new()),
            local_ip_finder: Box::new(LocalIpFinderReal::new()),
            mapping_nonce_factory: Box::new(MappingNonceFactoryReal::new()),
            free_port_factory: Box::new(FreePortFactoryReal::new()),
        }
    }
}

pub struct PcpTransactor {
    factories_arc: Arc<Mutex<Factories>>,
    router_port: u16,
    listen_port: u16,
    change_handler_config: RefCell<Option<ChangeHandlerConfig>>,
    change_handler_stopper: Option<Sender<()>>,
    logger: Logger,
}

impl Transactor for PcpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        find_routers()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        let (result_code, _epoch_time, opcode_data) =
            Self::mapping_transaction(&self.factories_arc, router_ip, self.router_port, 0x0009, 0)?;
        match result_code {
            ResultCode::Success => Ok(opcode_data.external_ip_address),
            code => Err(AutomapError::TransactionFailure(format!("{:?}", code))),
        }
    }

    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        self.change_handler_config
            .borrow_mut()
            .replace(ChangeHandlerConfig {
                hole_port,
                lifetime,
            });
        let (result_code, _epoch_time, _opcode_data) = Self::mapping_transaction(
            &self.factories_arc,
            router_ip,
            self.router_port,
            hole_port,
            lifetime,
        )?;
        match result_code {
            ResultCode::Success => Ok(lifetime / 2),
            code => Err(AutomapError::TransactionFailure(format!("{:?}", code))),
        }
    }

    fn add_permanent_mapping(
        &self,
        _router_ip: IpAddr,
        _hole_port: u16,
    ) -> Result<u32, AutomapError> {
        panic!("PCP cannot add permanent mappings")
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        let (result_code, _epoch_time, _opcode_data) = Self::mapping_transaction(
            &self.factories_arc,
            router_ip,
            self.router_port,
            hole_port,
            0,
        )?;
        match result_code {
            ResultCode::Success => Ok(()),
            code => Err(AutomapError::TransactionFailure(format!("{:?}", code))),
        }
    }

    fn method(&self) -> AutomapProtocol {
        AutomapProtocol::Pcp
    }

    fn start_change_handler(&mut self, change_handler: ChangeHandler) -> Result<(), AutomapError> {
        if let Some(_change_handler_stopper) = &self.change_handler_stopper {
            return Err(AutomapError::ChangeHandlerAlreadyRunning);
        }
        let change_handler_config = match self.change_handler_config.borrow().deref() {
            None => return Err(AutomapError::ChangeHandlerUnconfigured),
            Some(chc) => chc.clone(),
        };
        let ip_addr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
        let socket_addr = SocketAddr::new(ip_addr, self.listen_port);
        let socket_result = {
            let factories = self.factories_arc.lock().expect("Automap is poisoned!");
            factories.socket_factory.make(socket_addr)
        };
        let socket = match socket_result {
            Ok(s) => s,
            Err(e) => {
                return Err(AutomapError::SocketBindingError(
                    format!("{:?}", e),
                    socket_addr,
                ))
            }
        };
        let (tx, rx) = unbounded();
        self.change_handler_stopper = Some(tx);
        let factories_arc = self.factories_arc.clone();
        let router_port = self.router_port;
        let logger = self.logger.clone();
        thread::spawn(move || {
            Self::thread_guts(
                &socket,
                &rx,
                factories_arc,
                router_port,
                &change_handler,
                change_handler_config,
                logger,
            )
        });
        Ok(())
    }

    fn stop_change_handler(&mut self) {
        match self.change_handler_stopper.take() {
            Some(stopper) => {
                let _ = stopper.send(());
            }
            None => (), // Objective already achieved
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Default for PcpTransactor {
    fn default() -> Self {
        Self {
            factories_arc: Arc::new(Mutex::new(Factories::default())),
            router_port: ROUTER_PORT,
            listen_port: CHANGE_HANDLER_PORT,
            change_handler_config: RefCell::new(None),
            change_handler_stopper: None,
            logger: Logger::new("Automap"),
        }
    }
}

impl PcpTransactor {
    fn mapping_transaction(
        factories_arc: &Arc<Mutex<Factories>>,
        router_ip: IpAddr,
        router_port: u16,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<(ResultCode, u32, MapOpcodeData), AutomapError> {
        let (socket_addr, socket_result, local_ip_result, mapping_nonce) =
            Self::employ_factories(factories_arc, router_ip);
        let packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime,
            client_ip_opt: Some(local_ip_result?),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce,
                protocol: Protocol::Tcp,
                internal_port: hole_port,
                external_port: hole_port,
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
                return Err(AutomapError::SocketBindingError(
                    format!("{:?}", e),
                    socket_addr,
                ))
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set_read_timeout failed");
        match socket.send_to(
            &buffer[0..request_len],
            SocketAddr::new(router_ip, router_port),
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                    format!("{:?}", e),
                )))
            }
        };
        let response = match socket.recv_from(&mut buffer) {
            Ok((len, _peer_addr)) => match PcpPacket::try_from(&buffer[0..len]) {
                Ok(pkt) => pkt,
                Err(e) => return Err(AutomapError::PacketParseError(e)),
            },
            Err(e) if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) => {
                return Err(AutomapError::ProtocolError(
                    "Timed out after 3 seconds".to_string(),
                ))
            }
            Err(e) => {
                return Err(AutomapError::SocketReceiveError(
                    AutomapErrorCause::Unknown(format!("{:?}", e)),
                ))
            }
        };
        if response.direction != Direction::Response {
            return Err(AutomapError::ProtocolError(
                "Map response labeled as request".to_string(),
            ));
        }
        if response.opcode != Opcode::Map {
            return Err(AutomapError::ProtocolError(format!(
                "Map response has opcode {:?} instead of Map",
                response.opcode
            )));
        }
        let result_code = response
            .result_code_opt
            .expect("Response parsing inoperative - result code");
        let epoch_time = response
            .epoch_time_opt
            .expect("Response parsing inoperative - epoch time");
        let opcode_data = response
            .opcode_data
            .as_any()
            .downcast_ref::<MapOpcodeData>()
            .expect("Response parsing inoperative - opcode data");
        Ok((result_code, epoch_time, opcode_data.clone()))
    }

    fn employ_factories(
        factories_arc: &Arc<Mutex<Factories>>,
        router_ip: IpAddr,
    ) -> (
        SocketAddr,
        io::Result<Box<dyn UdpSocketWrapper>>,
        Result<IpAddr, AutomapError>,
        [u8; 12],
    ) {
        let factories = factories_arc.lock().expect("Automap is poisoned!");
        let free_port = factories.free_port_factory.make();
        let socket_addr = make_local_socket_address(router_ip, free_port);
        (
            socket_addr,
            factories.socket_factory.make(socket_addr),
            factories.local_ip_finder.find(),
            factories.mapping_nonce_factory.make(),
        )
    }

    fn thread_guts(
        socket: &Box<dyn UdpSocketWrapper>,
        rx: &Receiver<()>,
        factories_arc: Arc<Mutex<Factories>>,
        router_port: u16,
        change_handler: &ChangeHandler,
        change_handler_config: ChangeHandlerConfig,
        logger: Logger,
    ) {
        let change_handler_lifetime = change_handler_config.lifetime;
        let mut buffer = [0u8; 100];
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("Can't set read timeout");
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((len, router_address)) => match PcpPacket::try_from(&buffer[0..len]) {
                    Ok(packet) => {
                        if packet.opcode == Opcode::Announce {
                            Self::handle_announcement(
                                factories_arc.clone(),
                                router_address.ip(),
                                router_port,
                                change_handler_config.hole_port,
                                change_handler,
                                change_handler_lifetime,
                                &logger,
                            );
                        }
                    }
                    Err(_) => error!(
                        logger,
                        "Unparseable PCP packet:\n{}",
                        PrettyHex::hex_dump(&&buffer[0..len])
                    ),
                },
                Err(e)
                    if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) =>
                {
                    ()
                }
                Err(e) => error!(logger, "Error receiving PCP packet from router: {:?}", e),
            }
            match rx.try_recv() {
                Ok(_) => break,
                Err(_) => (),
            }
        }
    }

    fn handle_announcement(
        factories_arc: Arc<Mutex<Factories>>,
        router_ip: IpAddr,
        router_port: u16,
        hole_port: u16,
        change_handler: &ChangeHandler,
        change_handler_lifetime: u32,
        logger: &Logger,
    ) {
        match Self::mapping_transaction(
            &factories_arc,
            router_ip,
            router_port,
            hole_port,
            change_handler_lifetime,
        ) {
            Ok((_, _, opcode_data)) => {
                change_handler(AutomapChange::NewIp(opcode_data.external_ip_address))
            }
            Err(e) => {
                error!(
                    logger,
                    "Remapping after IP change failed, Node is useless: {:?}", e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::pcp_pmp_common::mocks::{
        FreePortFactoryMock, UdpSocketFactoryMock, UdpSocketMock,
    };
    use crate::comm_layer::pcp_pmp_common::ROUTER_PORT;
    use crate::comm_layer::{AutomapErrorCause, LocalIpFinder};
    use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
    use crate::protocols::pcp::pcp_packet::{Opcode, PcpPacket};
    use crate::protocols::utils::{Direction, Packet, ParseError, UnrecognizedData};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::{find_free_port, localhost};
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::io::ErrorKind;
    use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::{io, thread};

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

    #[test]
    fn knows_its_method() {
        let subject = PcpTransactor::default();

        let method = subject.method();

        assert_eq!(method, AutomapProtocol::Pcp);
    }

    #[test]
    fn mapping_nonce_factory_works() {
        let mut value_sets: Vec<HashSet<u8>> =
            (0..12).into_iter().map(|_| HashSet::new()).collect();
        let subject = MappingNonceFactoryReal::new();
        for _ in 0..10 {
            let nonce = subject.make();
            for n in 0..12 {
                value_sets[n].insert(nonce[n]);
            }
        }
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
    fn mapping_transaction_handles_socket_factory_error() {
        let router_ip = IpAddr::from_str("192.168.0.1").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket_factory = UdpSocketFactoryMock::new().make_result(Err(io_error));
        let free_port_factory = FreePortFactoryMock::new().make_result(5566);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
            factories.free_port_factory = Box::new(free_port_factory);
        }

        let result = PcpTransactor::mapping_transaction(
            &subject.factories_arc,
            router_ip,
            ROUTER_PORT,
            6666,
            4321,
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
    }

    #[test]
    fn mapping_transaction_handles_send_to_error() {
        let router_ip = IpAddr::from_str("192.168.0.1").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Err(io_error));
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
        }

        let result = PcpTransactor::mapping_transaction(
            &subject.factories_arc,
            router_ip,
            ROUTER_PORT,
            6666,
            4321,
        );

        assert_eq!(
            result,
            Err(AutomapError::SocketSendError(AutomapErrorCause::Unknown(
                io_error_str
            )))
        );
    }

    #[test]
    fn mapping_transaction_handles_recv_from_error() {
        let router_ip = IpAddr::from_str("192.168.0.1").unwrap();
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let io_error_str = format!("{:?}", io_error);
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(Err(io_error), vec![]);
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
        }

        let result = PcpTransactor::mapping_transaction(
            &subject.factories_arc,
            router_ip,
            ROUTER_PORT,
            6666,
            4321,
        );

        assert_eq!(
            result,
            Err(AutomapError::SocketReceiveError(
                AutomapErrorCause::Unknown(io_error_str)
            ))
        );
    }

    #[test]
    fn mapping_transaction_handles_packet_parse_error() {
        let router_ip = IpAddr::from_str("192.168.0.1").unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(Ok((0, SocketAddr::new(router_ip, ROUTER_PORT))), vec![]);
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
        }

        let result = PcpTransactor::mapping_transaction(
            &subject.factories_arc,
            router_ip,
            ROUTER_PORT,
            6666,
            4321,
        );

        assert_eq!(
            result,
            Err(AutomapError::PacketParseError(ParseError::ShortBuffer(
                24, 0
            )))
        );
    }

    #[test]
    fn mapping_transaction_handles_wrong_direction() {
        let router_ip = IpAddr::from_str("192.168.0.1").unwrap();
        let mut buffer = [0u8; 1100];
        let packet = vanilla_request();
        let len = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((len, SocketAddr::new(router_ip, ROUTER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
        }

        let result = PcpTransactor::mapping_transaction(
            &subject.factories_arc,
            router_ip,
            ROUTER_PORT,
            6666,
            4321,
        );

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(
                "Map response labeled as request".to_string()
            ))
        );
    }

    #[test]
    fn mapping_transaction_handles_unexpected_opcode() {
        let router_ip = IpAddr::from_str("192.168.0.1").unwrap();
        let mut buffer = [0u8; 1100];
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Other(127);
        let len = packet.marshal(&mut buffer).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((len, SocketAddr::new(router_ip, ROUTER_PORT))),
                buffer[0..len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
        }

        let result = PcpTransactor::mapping_transaction(
            &subject.factories_arc,
            router_ip,
            ROUTER_PORT,
            6666,
            4321,
        );

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError(
                "Map response has opcode Other(127) instead of Map".to_string()
            ))
        );
    }

    #[test]
    fn find_routers_returns_something_believable() {
        let subject = PcpTransactor::default();

        let result = subject.find_routers().unwrap();

        assert_eq!(result.len(), 1)
    }

    #[test]
    fn get_public_ip_works() {
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let mut request_packet = vanilla_request();
        request_packet.opcode = Opcode::Map;
        request_packet.lifetime = 0;
        let mut opcode_data = vanilla_map_request();
        opcode_data.internal_port = 0x0009;
        opcode_data.external_port = 0x0009;
        request_packet.opcode_data = opcode_data;
        let mut request = [0u8; 1100];
        let _request_len = request_packet.marshal(&mut request).unwrap();
        let mut response_packet = vanilla_response();
        response_packet.opcode = Opcode::Map;
        response_packet.lifetime = 0;
        response_packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = response_packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
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
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
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
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.result_code_opt = Some(ResultCode::AddressMismatch);
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.get_public_ip(IpAddr::from_str("1.2.3.4").unwrap());

        assert_eq!(
            result,
            Err(AutomapError::TransactionFailure(
                "AddressMismatch".to_string()
            ))
        );
    }

    #[test]
    fn add_mapping_works() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let mut packet = vanilla_request();
        packet.opcode = Opcode::Map;
        packet.opcode_data = vanilla_map_request();
        let mut request = [0x00u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_params(&read_timeout_params_arc)
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
        let socket_factory = UdpSocketFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let free_port_factory = FreePortFactoryMock::new().make_result(34567);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
            factories.free_port_factory = Box::new(free_port_factory);
        }

        let result = subject.add_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666, 1234);

        assert_eq!(result, Ok(617));
        if let Some(chc) = subject.change_handler_config.borrow().deref() {
            assert_eq!(chc.hole_port, 6666);
            assert_eq!(chc.lifetime, 1234);
        } else {
            panic!("change_handler_config not set");
        }
        assert!(subject.change_handler_stopper.is_none());
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_str("0.0.0.0").unwrap(),
                34567
            ))]
        );
        let read_timeout_params = read_timeout_params_arc.lock().unwrap();
        assert_eq!(*read_timeout_params, vec![Some(Duration::from_secs(3))]);
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
    fn add_mapping_handles_failure() {
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.result_code_opt = Some(ResultCode::AddressMismatch);
        let opcode_data = vanilla_map_response();
        packet.opcode_data = opcode_data;
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.add_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666, 1234);

        assert_eq!(
            result,
            Err(AutomapError::TransactionFailure(
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
        let read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let mut packet = vanilla_request();
        packet.opcode = Opcode::Map;
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_request();
        let mut request = [0x00u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Map;
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_params(&read_timeout_params_arc)
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
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.delete_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666);

        assert_eq!(result, Ok(()));
        let read_timeout_params = read_timeout_params_arc.lock().unwrap();
        assert_eq!(*read_timeout_params, vec![Some(Duration::from_secs(3))]);
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
        packet.result_code_opt = Some(ResultCode::AddressMismatch);
        packet.lifetime = 0;
        packet.opcode_data = vanilla_map_response();
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((
                    1000,
                    SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), ROUTER_PORT),
                )),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let subject = PcpTransactor::default();
        {
            let mut factories = subject.factories_arc.lock().unwrap();
            factories.socket_factory = Box::new(socket_factory);
            factories.mapping_nonce_factory = Box::new(nonce_factory);
        }

        let result = subject.delete_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666);

        assert_eq!(
            result,
            Err(AutomapError::TransactionFailure(
                "AddressMismatch".to_string()
            ))
        );
    }

    #[test]
    fn change_handler_works() {
        let change_handler_port = find_free_port();
        let router_port = find_free_port();
        let mut subject = PcpTransactor::default();
        subject.router_port = router_port;
        subject.listen_port = change_handler_port;
        subject.change_handler_config = RefCell::new(Some(ChangeHandlerConfig {
            hole_port: 1234,
            lifetime: 321,
        }));
        let changes_arc = Arc::new(Mutex::new(vec![]));
        let changes_arc_inner = changes_arc.clone();
        let change_handler = move |change| {
            changes_arc_inner.lock().unwrap().push(change);
        };

        subject
            .start_change_handler(Box::new(change_handler))
            .unwrap();

        assert!(subject.change_handler_stopper.is_some());
        let change_handler_ip = IpAddr::from_str("224.0.0.1").unwrap();
        let announce_socket = UdpSocket::bind(SocketAddr::new(localhost(), 0)).unwrap();
        announce_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        announce_socket.set_broadcast(true).unwrap();
        announce_socket
            .connect(SocketAddr::new(change_handler_ip, change_handler_port))
            .unwrap();
        let mut packet = vanilla_response();
        packet.opcode = Opcode::Announce;
        packet.lifetime = 0;
        packet.epoch_time_opt = Some(0);
        let mut buffer = [0u8; 100];
        let len_to_send = packet.marshal(&mut buffer).unwrap();
        let mapping_socket = UdpSocket::bind(SocketAddr::new(localhost(), router_port)).unwrap();
        let sent_len = announce_socket.send(&buffer[0..len_to_send]).unwrap();
        assert_eq!(sent_len, len_to_send);
        let (recv_len, remapping_socket_addr) = mapping_socket.recv_from(&mut buffer).unwrap();
        let packet = PcpPacket::try_from(&buffer[0..recv_len]).unwrap();
        assert_eq!(packet.opcode, Opcode::Map);
        assert_eq!(packet.lifetime, 321);
        let opcode_data: &MapOpcodeData = packet.opcode_data.as_any().downcast_ref().unwrap();
        assert_eq!(opcode_data.external_port, 1234);
        assert_eq!(opcode_data.internal_port, 1234);
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
        thread::sleep(Duration::from_millis(1)); // yield timeslice
        subject.stop_change_handler();
        assert!(subject.change_handler_stopper.is_none());
        let changes = changes_arc.lock().unwrap();
        assert_eq!(
            *changes,
            vec![AutomapChange::NewIp(IpAddr::from_str("4.5.6.7").unwrap())]
        )
    }

    #[test]
    fn start_change_handler_doesnt_work_if_change_handler_stopper_is_populated() {
        let mut subject = PcpTransactor::default();
        subject.change_handler_stopper = Some(unbounded().0);
        let change_handler = move |_| {};

        let result = subject.start_change_handler(Box::new(change_handler));

        assert_eq!(result, Err(AutomapError::ChangeHandlerAlreadyRunning))
    }

    #[test]
    fn start_change_handler_doesnt_work_if_change_handler_is_unconfigured() {
        let mut subject = PcpTransactor::default();
        subject.change_handler_config = RefCell::new(None);
        let change_handler = move |_| {};

        let result = subject.start_change_handler(Box::new(change_handler));

        assert_eq!(result, Err(AutomapError::ChangeHandlerUnconfigured))
    }

    #[test]
    fn stop_change_handler_handles_missing_change_handler_stopper() {
        let mut subject = PcpTransactor::default();
        subject.change_handler_stopper = None;

        subject.stop_change_handler();

        // no panic: test passes
    }

    #[test]
    fn thread_guts_logs_if_error_receiving_pcp_packet() {
        init_test_logging();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Err(io::Error::from(ErrorKind::BrokenPipe)), vec![]),
        );
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let logger = Logger::new("Automap");
        tx.send(()).unwrap();

        PcpTransactor::thread_guts(
            &socket,
            &rx,
            Arc::new(Mutex::new(Factories::default())),
            0,
            &change_handler,
            ChangeHandlerConfig {
                hole_port: 0,
                lifetime: 0,
            },
            logger,
        );

        TestLogHandler::new().exists_log_containing(
            "ERROR: Automap: Error receiving PCP packet from router: Kind(BrokenPipe)",
        );
    }

    #[test]
    fn thread_guts_logs_if_unparseable_pcp_packet_arrives() {
        init_test_logging();
        let socket_addr = SocketAddr::from_str("1.1.1.1:1").unwrap();
        let (tx, rx) = unbounded();
        let socket: Box<dyn UdpSocketWrapper> = Box::new(
            UdpSocketMock::new()
                .set_read_timeout_result(Ok(()))
                .recv_from_result(Ok((5, socket_addr)), b"booga".to_vec()),
        );
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let logger = Logger::new("Automap");
        tx.send(()).unwrap();

        PcpTransactor::thread_guts(
            &socket,
            &rx,
            Arc::new(Mutex::new(Factories::default())),
            0,
            &change_handler,
            ChangeHandlerConfig {
                hole_port: 0,
                lifetime: 0,
            },
            logger,
        );

        TestLogHandler::new().exists_log_containing("ERROR: Automap: Unparseable PCP packet:");
    }

    // TODO: This is not really what we want, but I don't know exactly what we really do want. When
    // this happens, the Node is useless until the port can be remapped. How do we handle that
    // situation?
    #[test]
    fn handle_announcement_logs_if_remapping_fails() {
        init_test_logging();
        let mut factories = Factories::default();
        factories.socket_factory = Box::new(
            UdpSocketFactoryMock::new().make_result(Err(io::Error::from(ErrorKind::AlreadyExists))),
        );
        let change_handler: ChangeHandler = Box::new(move |_| {});
        let logger = Logger::new("Automap");

        PcpTransactor::handle_announcement(
            Arc::new(Mutex::new(factories)),
            localhost(),
            0,
            0,
            &change_handler,
            0,
            &logger,
        );

        TestLogHandler::new().exists_log_containing ("ERROR: Automap: Remapping after IP change failed, Node is useless: SocketBindingError(\"Kind(AlreadyExists)\", 0.0.0.0:");
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
}
