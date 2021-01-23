// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::{Transactor, AutomapError};
use std::net::{IpAddr, SocketAddr};
use crate::comm_layer::pcp_pmp_common::{UdpSocketFactory, UdpSocketFactoryReal};
use crate::protocols::pmp::pmp_packet::{PmpPacket, Opcode, ResultCode};
use crate::protocols::utils::{Direction, Packet};
use crate::protocols::pmp::get_packet::GetOpcodeData;
use std::time::Duration;
use std::convert::TryFrom;
use crate::protocols::pmp::map_packet::MapOpcodeData;

pub struct PmpTransactor {
    socket_factory: Box<dyn UdpSocketFactory>,
}

impl Transactor for PmpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
        unimplemented!()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
        let request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: None
            })
        };
        let response = self.transact (router_ip, request)?;
        let opcode_data = match response.opcode_data.as_any().downcast_ref::<GetOpcodeData>() {
            Some (data) => data,
            None => unimplemented! (),
        };
        match opcode_data.external_ip_address_opt {
            Some (ip) => Ok (IpAddr::V4 (ip)),
            None => unimplemented! (),
        }
    }

    fn add_mapping(&self, router_ip: IpAddr, hole_port: u16, lifetime: u32) -> Result<u32, AutomapError> {
        let request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::MapTcp,
            result_code_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                epoch_opt: None,
                internal_port: hole_port,
                external_port: hole_port,
                lifetime,
            })
        };
        let response = self.transact (router_ip, request)?;
        match response.result_code_opt {
            Some (ResultCode::Success) => Ok (lifetime / 2),
            Some (rc) => unimplemented!("{:?}", rc),
            None => unimplemented!(),
        }
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
        self.add_mapping(router_ip, hole_port, 0)?;
        Ok(())
    }
}

impl Default for PmpTransactor {
    fn default() -> Self {
        Self {
            socket_factory: Box::new (UdpSocketFactoryReal::new()),
        }
    }
}

impl PmpTransactor {
    pub fn new () -> Self {
        Self::default()
    }

    fn transact (&self, router_ip: IpAddr, request: PmpPacket) -> Result<PmpPacket, AutomapError> {
        let mut buffer = [0u8; 1100];
        let len = match request.marshal (&mut buffer) {
            Ok (len) => len,
            Err (e) => unimplemented!("{:?}", e),
        };
        let socket = match self.socket_factory.make (SocketAddr::new (router_ip, 5351)) {
            Ok (s) => s,
            Err (e) => unimplemented! ("{:?}", e),
        };
        if let Err(e) = socket.set_read_timeout(Some (Duration::from_millis (250))) {
            unimplemented!("{:?}", e);
        }
        if let Err(e) = socket.send_to (&buffer[0..len], SocketAddr::new (router_ip, 5351)) {
            unimplemented! ("{:?}", e);
        }
        let (len, _) = match socket.recv_from(&mut buffer) {
            Ok (len) => len,
            Err (e) => unimplemented! ("{:?}", e),
        };
        let response = match PmpPacket::try_from (&buffer[0..len]) {
            Ok (pkt) => pkt,
            Err (e) => unimplemented! ("{:?}", e),
        };
        match response.result_code_opt {
            Some (ResultCode::Success) => (),
            Some (rc) => unimplemented!("{:?}", rc),
            None => unimplemented! (),
        };
        Ok (response)
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::protocols::pmp::pmp_packet::{PmpPacket, Opcode, ResultCode};
    use crate::protocols::utils::{Direction, Packet};
    use crate::protocols::pmp::get_packet::GetOpcodeData;
    use crate::comm_layer::pcp_pmp_common::mocks::{UdpSocketFactoryMock, UdpSocketMock};
    use std::net::{SocketAddr, Ipv4Addr};
    use std::sync::{Mutex, Arc};
    use std::time::Duration;
    use crate::protocols::pmp::map_packet::MapOpcodeData;

    #[test]
    fn get_public_ip_works() {
        let router_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let public_ip = Ipv4Addr::from_str("72.73.74.75").unwrap();
        let mut request_buffer = [0u8; 1100];
        let request = PmpPacket {
            direction: Direction::Request,
            opcode: Opcode::Get,
            result_code_opt: None,
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: None,
                external_ip_address_opt: None
            }),
        };
        let request_len = request.marshal (&mut request_buffer).unwrap();
        let mut response_buffer = [0u8; 1100];
        let response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::Get,
            result_code_opt: Some(ResultCode::Success),
            opcode_data: Box::new(GetOpcodeData {
                epoch_opt: Some (1234),
                external_ip_address_opt: Some (public_ip)
            })
        };
        let response_len = response.marshal (&mut response_buffer).unwrap();
        let set_read_timeout_params_arc = Arc::new (Mutex::new (vec![]));
        let send_to_params_arc = Arc::new (Mutex::new (vec![]));
        let recv_from_params_arc = Arc::new (Mutex::new (vec![]));
        let socket = UdpSocketMock::new()
            .set_read_timeout_params (&set_read_timeout_params_arc)
            .set_read_timeout_result (Ok(()))
            .send_to_params (&send_to_params_arc)
            .send_to_result (Ok(request_len))
            .recv_from_params (&recv_from_params_arc)
            .recv_from_result (Ok ((response_len, SocketAddr::new (router_ip, 5351))), response_buffer[0..response_len].to_vec());
        let socket_factory = UdpSocketFactoryMock::new()
            .make_result (Ok (socket));
        let mut subject = PmpTransactor::default();
        subject.socket_factory = Box::new (socket_factory);

        let result = subject.get_public_ip (router_ip);

        assert_eq! (result, Ok (IpAddr::V4 (public_ip)));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq! (*set_read_timeout_params, vec![Some (Duration::from_millis (250))]);
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq! (*send_to_params, vec! [
            (request_buffer[0..request_len].to_vec(), SocketAddr::new (router_ip, 5351))
        ]);
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq! (*recv_from_params, vec![()])
    }

    #[test]
    fn add_mapping_works() {
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
                lifetime: 1234
            }),
        };
        let request_len = request.marshal (&mut request_buffer).unwrap();
        let mut response_buffer = [0u8; 1100];
        let response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::MapTcp,
            result_code_opt: Some(ResultCode::Success),
            opcode_data: Box::new(MapOpcodeData {
                epoch_opt: Some(4321),
                internal_port: 7777,
                external_port: 7777,
                lifetime: 1234
            })
        };
        let response_len = response.marshal (&mut response_buffer).unwrap();
        let set_read_timeout_params_arc = Arc::new (Mutex::new (vec![]));
        let send_to_params_arc = Arc::new (Mutex::new (vec![]));
        let recv_from_params_arc = Arc::new (Mutex::new (vec![]));
        let socket = UdpSocketMock::new()
            .set_read_timeout_params (&set_read_timeout_params_arc)
            .set_read_timeout_result (Ok(()))
            .send_to_params (&send_to_params_arc)
            .send_to_result (Ok(request_len))
            .recv_from_params (&recv_from_params_arc)
            .recv_from_result (Ok ((response_len, SocketAddr::new (router_ip, 5351))), response_buffer[0..response_len].to_vec());
        let socket_factory = UdpSocketFactoryMock::new()
            .make_result (Ok (socket));
        let mut subject = PmpTransactor::default();
        subject.socket_factory = Box::new (socket_factory);

        let result = subject.add_mapping (router_ip, 7777, 1234);

        assert_eq! (result, Ok (617));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq! (*set_read_timeout_params, vec![Some (Duration::from_millis (250))]);
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq! (*send_to_params, vec! [
            (request_buffer[0..request_len].to_vec(), SocketAddr::new (router_ip, 5351))
        ]);
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq! (*recv_from_params, vec![()])
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
                lifetime: 0
            }),
        };
        let request_len = request.marshal (&mut request_buffer).unwrap();
        let mut response_buffer = [0u8; 1100];
        let response = PmpPacket {
            direction: Direction::Response,
            opcode: Opcode::MapTcp,
            result_code_opt: Some(ResultCode::Success),
            opcode_data: Box::new(MapOpcodeData {
                epoch_opt: Some(4321),
                internal_port: 7777,
                external_port: 7777,
                lifetime: 0
            })
        };
        let response_len = response.marshal (&mut response_buffer).unwrap();
        let set_read_timeout_params_arc = Arc::new (Mutex::new (vec![]));
        let send_to_params_arc = Arc::new (Mutex::new (vec![]));
        let recv_from_params_arc = Arc::new (Mutex::new (vec![]));
        let socket = UdpSocketMock::new()
            .set_read_timeout_params (&set_read_timeout_params_arc)
            .set_read_timeout_result (Ok(()))
            .send_to_params (&send_to_params_arc)
            .send_to_result (Ok(request_len))
            .recv_from_params (&recv_from_params_arc)
            .recv_from_result (Ok ((response_len, SocketAddr::new (router_ip, 5351))), response_buffer[0..response_len].to_vec());
        let socket_factory = UdpSocketFactoryMock::new()
            .make_result (Ok (socket));
        let mut subject = PmpTransactor::default();
        subject.socket_factory = Box::new (socket_factory);

        let result = subject.delete_mapping (router_ip, 7777);

        assert_eq! (result, Ok (()));
        let set_read_timeout_params = set_read_timeout_params_arc.lock().unwrap();
        assert_eq! (*set_read_timeout_params, vec![Some (Duration::from_millis (250))]);
        let send_to_params = send_to_params_arc.lock().unwrap();
        assert_eq! (*send_to_params, vec! [
            (request_buffer[0..request_len].to_vec(), SocketAddr::new (router_ip, 5351))
        ]);
        let recv_from_params = recv_from_params_arc.lock().unwrap();
        assert_eq! (*recv_from_params, vec![()])
    }
}
