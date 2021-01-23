// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pcp_pmp_common::{
    FreePortFactory, FreePortFactoryReal, UdpSocketFactory, UdpSocketFactoryReal,
};
use crate::comm_layer::{AutomapError, Transactor};
use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
use crate::protocols::pcp::pcp_packet::{Opcode, PcpPacket, ResultCode};
use crate::protocols::utils::{Direction, Packet};
use rand::RngCore;
use std::cell::RefCell;
use std::collections::hash_map::RandomState;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

trait MappingNonceFactory {
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

pub struct PcpTransactor {
    socket_factory: Box<dyn UdpSocketFactory>,
    mapping_nonce_factory: Box<dyn MappingNonceFactory>,
}

impl Transactor for PcpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        unimplemented!()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        let (result_code, epoch_time, opcode_data) =
            self.mapping_transaction(router_ip, 10000, 0)?;
        match result_code {
            ResultCode::Success => Ok(opcode_data.external_ip_address),
            x => unimplemented!("{:?}", x),
        }
    }

    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError> {
        let (result_code, epoch_time, opcode_data) =
            self.mapping_transaction(router_ip, hole_port, lifetime)?;
        match result_code {
            ResultCode::Success => Ok(lifetime / 2),
            x => unimplemented!("{:?}", x),
        }
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        let (result_code, epoch_time, opcode_data) =
            self.mapping_transaction(router_ip, hole_port, 0)?;
        match result_code {
            ResultCode::Success => Ok(()),
            x => unimplemented!("{:?}", x),
        }
    }
}

impl Default for PcpTransactor {
    fn default() -> Self {
        Self {
            socket_factory: Box::new(UdpSocketFactoryReal::new()),
            mapping_nonce_factory: Box::new(MappingNonceFactoryReal::new()),
        }
    }
}

impl PcpTransactor {
    fn mapping_transaction(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<(ResultCode, u32, MapOpcodeData), AutomapError> {
        let my_ip = match local_ipaddress::get() {
            Some(my_ip_str) => match IpAddr::from_str(&my_ip_str) {
                Ok(ip) => ip,
                Err(e) => unimplemented!("{:?}", e),
            },
            None => unimplemented!(),
        };
        let packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime,
            client_ip_opt: Some(my_ip),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: self.mapping_nonce_factory.make(),
                protocol: Protocol::Tcp,
                internal_port: hole_port,
                external_port: hole_port,
                external_ip_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            }),
            options: vec![],
        };
        let mut buffer = [0u8; 1100];
        let request_len = match packet.marshal(&mut buffer) {
            Ok(len) => len,
            Err(e) => unimplemented!("{:?}", e),
        };
        let socket = match self.socket_factory.make(SocketAddr::new(router_ip, 5351)) {
            Ok(s) => s,
            Err(e) => unimplemented!("{:?}", e),
        };
        match socket.set_read_timeout(Some(Duration::from_secs(3))) {
            Ok(_) => (),
            Err(e) => unimplemented!("{:?}", e),
        };
        match socket.send_to(&buffer[0..request_len], SocketAddr::new(router_ip, 5351)) {
            Ok(_) => (),
            Err(e) => unimplemented!("{:?}", e),
        };
        let response = match socket.recv_from(&mut buffer) {
            Ok((len, peer_addr)) => match PcpPacket::try_from(&buffer[0..len]) {
                Ok(pkt) => pkt,
                Err(e) => unimplemented!("{:?}", e),
            },
            Err(e) => unimplemented!("{:?}", e),
        };
        let result_code = match response.result_code_opt {
            Some(rc) => rc,
            None => unimplemented!(),
        };
        let epoch_time = match response.epoch_time_opt {
            Some(et) => et,
            None => unimplemented!(),
        };
        let opcode_data = match response
            .opcode_data
            .as_any()
            .downcast_ref::<MapOpcodeData>()
        {
            Some(data) => data,
            None => unimplemented!(),
        };
        Ok((result_code, epoch_time, opcode_data.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::pcp_pmp_common::mocks::{
        FreePortFactoryMock, UdpSocketFactoryMock, UdpSocketMock,
    };
    use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
    use crate::protocols::pcp::pcp_packet::ResultCode::Success;
    use crate::protocols::pcp::pcp_packet::{Opcode, PcpPacket};
    use crate::protocols::utils::{Direction, Packet};
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
    fn get_public_ip_works() {
        let my_ip = IpAddr::from_str(&local_ipaddress::get().unwrap()).unwrap();
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: 0,
            client_ip_opt: Some(my_ip),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: Protocol::Tcp,
                internal_port: 10000,
                external_port: 10000,
                external_ip_address: IpAddr::from_str("0.0.0.0").unwrap(),
            }),
            options: vec![],
        };
        let mut request = [0u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let packet = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Map,
            result_code_opt: Some(Success),
            lifetime: 0,
            client_ip_opt: None,
            epoch_time_opt: Some(2345),
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: Protocol::Tcp,
                internal_port: 10000,
                external_port: 10000,
                external_ip_address: IpAddr::from_str("72.72.72.72").unwrap(),
            }),
            options: vec![],
        };
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(1000))
            .recv_from_result(
                Ok((1000, SocketAddr::from_str("1.2.3.4:5351").unwrap())),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let mut subject = PcpTransactor::default();
        subject.socket_factory = Box::new(socket_factory);
        subject.mapping_nonce_factory = Box::new(nonce_factory);

        let result = subject.get_public_ip(IpAddr::from_str("1.2.3.4").unwrap());

        assert_eq!(result, Ok(IpAddr::from_str("72.72.72.72").unwrap()));
    }

    #[test]
    fn add_mapping_works() {
        let my_ip = IpAddr::from_str(&local_ipaddress::get().unwrap()).unwrap();
        let read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: 1234,
            client_ip_opt: Some(my_ip),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: Protocol::Tcp,
                internal_port: 6666,
                external_port: 6666,
                external_ip_address: IpAddr::from_str("0.0.0.0").unwrap(),
            }),
            options: vec![],
        };
        let mut request = [0x00u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let packet = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Map,
            result_code_opt: Some(Success),
            lifetime: 1234,
            client_ip_opt: None,
            epoch_time_opt: Some(2345),
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: Protocol::Tcp,
                internal_port: 6666,
                external_port: 6666,
                external_ip_address: IpAddr::from_str("72.72.72.72").unwrap(),
            }),
            options: vec![],
        };
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_params(&read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(1000))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((1000, SocketAddr::from_str("1.2.3.4:5351").unwrap())),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let mut subject = PcpTransactor::default();
        subject.socket_factory = Box::new(socket_factory);
        subject.mapping_nonce_factory = Box::new(nonce_factory);

        let result = subject.add_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666, 1234);

        assert_eq!(result, Ok(617));
        let read_timeout_params = read_timeout_params_arc.lock().unwrap();
        assert_eq!(*read_timeout_params, vec![Some(Duration::from_secs(3))]);
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq!(
            *send_to_params,
            vec![(
                request[0..request_len].to_vec(),
                SocketAddr::from_str("1.2.3.4:5351").unwrap()
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()]);
    }

    #[test]
    fn delete_mapping_works() {
        let my_ip = IpAddr::from_str(&local_ipaddress::get().unwrap()).unwrap();
        let read_timeout_params_arc = Arc::new(Mutex::new(vec![]));
        let send_to_params_arc = Arc::new(Mutex::new(vec![]));
        let recv_from_params_arc = Arc::new(Mutex::new(vec![]));
        let packet = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: 0,
            client_ip_opt: Some(my_ip),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: Protocol::Tcp,
                internal_port: 6666,
                external_port: 6666,
                external_ip_address: IpAddr::from_str("0.0.0.0").unwrap(),
            }),
            options: vec![],
        };
        let mut request = [0x00u8; 1100];
        let request_len = packet.marshal(&mut request).unwrap();
        let packet = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Map,
            result_code_opt: Some(Success),
            lifetime: 0,
            client_ip_opt: None,
            epoch_time_opt: Some(2345),
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: Protocol::Tcp,
                internal_port: 6666,
                external_port: 6666,
                external_ip_address: IpAddr::from_str("72.72.72.72").unwrap(),
            }),
            options: vec![],
        };
        let mut response = [0u8; 1100];
        let response_len = packet.marshal(&mut response).unwrap();
        let socket = UdpSocketMock::new()
            .set_read_timeout_params(&read_timeout_params_arc)
            .set_read_timeout_result(Ok(()))
            .send_to_params(&send_to_params_arc)
            .send_to_result(Ok(1000))
            .recv_from_params(&recv_from_params_arc)
            .recv_from_result(
                Ok((1000, SocketAddr::from_str("1.2.3.4:5351").unwrap())),
                response[0..response_len].to_vec(),
            );
        let socket_factory = UdpSocketFactoryMock::new().make_result(Ok(socket));
        let nonce_factory =
            MappingNonceFactoryMock::new().make_result([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let mut subject = PcpTransactor::default();
        subject.socket_factory = Box::new(socket_factory);
        subject.mapping_nonce_factory = Box::new(nonce_factory);

        let result = subject.delete_mapping(IpAddr::from_str("1.2.3.4").unwrap(), 6666);

        assert_eq!(result, Ok(()));
        let read_timeout_params = read_timeout_params_arc.lock().unwrap();
        assert_eq!(*read_timeout_params, vec![Some(Duration::from_secs(3))]);
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq!(
            *send_to_params,
            vec![(
                request[0..request_len].to_vec(),
                SocketAddr::from_str("1.2.3.4:5351").unwrap()
            )]
        );
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq!(*recv_from_params, vec![()]);
    }
}
