// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::convert::From;
use std::net::{IpAddr, Ipv6Addr};
use std::any::Any;
use crate::pcp::map_packet::MapOpcodeData;

#[derive (Clone, PartialEq, Debug)]
pub enum Direction {
    Request,
    Response,
}

impl From<u8> for Direction {
    fn from(input: u8) -> Self {
        if (input & 0x80) > 0 {
            Direction::Response
        }
        else {
            Direction::Request
        }
    }
}

impl Direction {
    pub fn code (&self) -> u8 {
        match self {
            Direction::Request => 0x00,
            Direction::Response => 0x80,
        }
    }
}

#[derive (Clone, PartialEq, Debug)]
pub enum Opcode {
    Announce,
    Map,
    Peer,
    Other(u8),
}

impl From<u8> for Opcode {
    fn from(input: u8) -> Self {
        match input & 0x7F {
            0 => Opcode::Announce,
            1 => Opcode::Map,
            2 => Opcode::Peer,
            x => Opcode::Other (x)
        }
    }
}

impl Opcode {
    pub fn code (&self) -> u8 {
        match self {
            Opcode::Announce => 0,
            Opcode::Map => 1,
            Opcode::Peer => 2,
            Opcode::Other(code) => code & 0x7F,
        }
    }

    pub fn parse_data (&self, buf: &[u8]) -> Box<dyn OpcodeData> {
        match self {
            Opcode::Announce => unimplemented!(),
            Opcode::Map => Box::new (MapOpcodeData::new (buf)),
            Opcode::Peer => unimplemented!(),
            Opcode::Other(code) => Box::new (UnrecognizedData::new()),
        }
    }
}

pub trait OpcodeData {
    fn marshal (&self, buf: &mut [u8]) -> Result<(), PcpMarshalError>;
    fn len(&self) -> usize;
    fn as_any(&self) -> &dyn Any;
}

#[derive (PartialEq, Debug)]
pub struct UnrecognizedData {

}

impl OpcodeData for UnrecognizedData {
    fn marshal(&self, _buf: &mut [u8]) -> Result<(), PcpMarshalError> {
        Ok(())
    }

    fn len(&self) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UnrecognizedData {
    pub fn new () -> UnrecognizedData {
        UnrecognizedData {}
    }
}

pub trait PcpOption {

}

#[derive (Clone, PartialEq, Debug)]
pub enum PcpParseError {
    ShortBuffer,
}

#[derive (Clone, PartialEq, Debug)]
pub enum PcpMarshalError {
}

pub struct PcpPacket<'a> {
    buf: &'a mut [u8],
    pub version: u8,
    pub direction: Direction,
    pub opcode: Opcode,
    pub result_code_opt: Option<u8>,
    pub lifetime: u32,
    pub client_ip_opt: Option<IpAddr>,
    pub epoch_time_opt: Option<u32>,
    pub opcode_data: Box<dyn OpcodeData>,
    pub options: Vec<Box<dyn PcpOption>>,
}

impl<'a> PcpPacket<'a> {
    pub fn new(input: &'a mut [u8]) -> Result<Self, PcpParseError> {
        let mut result = PcpPacket {
            buf: input,
            version: 0,
            direction: Direction::Request,
            opcode: Opcode::Other (0),
            result_code_opt: None,
            lifetime: 0,
            client_ip_opt: None,
            epoch_time_opt: None,
            opcode_data: Box::new (UnrecognizedData::new()),
            options: vec![],
        };
        if result.buf.len() < 24 {
            return Err(PcpParseError::ShortBuffer)
        }
        result.version = result.buf[0];
        result.direction = Direction::from (result.buf[1]);
        result.opcode = Opcode::from (result.buf[1]);
        result.lifetime = u32_at (result.buf, 4);
        match result.direction {
            Direction::Request => {
                result.client_ip_opt = Some (ip_addr_at (result.buf, 8));
            },
            Direction::Response => {
                result.result_code_opt = Some (result.buf[3]);
                result.epoch_time_opt = Some (u32_at (result.buf, 8));
            },
        }
        result.opcode_data = result.opcode.parse_data (&result.buf[24..]);
        Ok(result)
    }

    pub fn marshal (&mut self) -> Result<usize, PcpMarshalError> {
        if self.buf.len() < (24 + self.opcode_data.len()) {
            unimplemented!()
        }
        self.buf[0] = self.version;
        self.buf[1] = self.direction.code() | self.opcode.code();
        self.buf[2] = 0x00;
        match self.direction {
            Direction::Request => self.buf[3] = 0x00,
            Direction::Response => self.buf[3] = self.result_code_opt.unwrap_or (0x00),
        }
        u32_into (self.buf, 4, self.lifetime);
        match self.direction {
            Direction::Request => match self.client_ip_opt {
                Some (ip_addr) => {
                    ip_addr_into (self.buf, 8, &ip_addr);
                },
                None => {
                    u32_into (self.buf, 8, 0);
                    u32_into (self.buf, 12, 0);
                    u32_into (self.buf, 16, 0);
                    u32_into (self.buf, 20, 0);
                }
            },
            Direction::Response => {
                u32_into (self.buf, 8, self.epoch_time_opt.unwrap_or(0));
                u32_into (self.buf, 12, 0);
                u32_into (self.buf, 16, 0);
                u32_into (self.buf, 20, 0);
            }
        }
        match self.opcode_data.marshal (&mut self.buf[24..]) {
            Ok (_) => Ok (24 + self.opcode_data.len()),
            Err (e) => unimplemented!("{:?}", e),
        }
    }
}

pub fn u32_at (buf: &[u8], offset: usize) -> u32 {
    ((buf[offset] as u32) << 24) +
        ((buf[offset + 1] as u32) << 16) +
        ((buf[offset + 2] as u32) << 8) +
        (buf[offset + 3] as u32)
}

pub fn u32_into (buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = (value >> 24) as u8;
    buf[offset + 1] = ((value >> 16) & 0xFF) as u8;
    buf[offset + 2] = ((value >> 8) & 0xFF) as u8;
    buf[offset + 3] = (value & 0xFF) as u8;
}

pub fn u16_at (buf: &[u8], offset: usize) -> u16 {
    ((buf[offset] as u16) << 8) +
        (buf[offset + 1] as u16)
}

pub fn u16_into (buf: &mut [u8], offset: usize, value: u16) {
    buf[offset] = (value >> 8) as u8;
    buf[offset + 1] = (value & 0xFF) as u8;
}

pub fn ip_addr_at (buf: &[u8], offset: usize) -> IpAddr {
    let ipv6_addr = Ipv6Addr::new(
        u16_at(buf, offset),
        u16_at(buf, offset + 2),
        u16_at(buf, offset + 4),
        u16_at(buf, offset + 6),
        u16_at(buf, offset + 8),
        u16_at(buf, offset + 10),
        u16_at(buf, offset + 12),
        u16_at(buf, offset + 14),
    );
    match ipv6_addr.to_ipv4() {
        Some (ipv4_addr) => IpAddr::V4 (ipv4_addr),
        None => IpAddr::V6 (ipv6_addr),
    }
}

pub fn ip_addr_into (buf: &mut [u8], offset: usize, value: &IpAddr) {
    let ipv6_addr = match value {
        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        IpAddr::V6(addr) => addr.clone(),
    };
    let octets = ipv6_addr.octets();
    for n in 0..16 {
        buf[offset + n] = octets[n]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::net::Ipv4Addr;
    use crate::pcp::map_packet::{MapOpcodeData, Protocol};

    #[test]
    fn from_works_for_unknown_request_with_ipv6() {
        let mut buffer: [u8; 24] = [
            0x12, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::new (&mut buffer).unwrap();

        assert_eq! (subject.version, 0x12);
        assert_eq! (subject.direction, Direction::Request);
        assert_eq! (subject.opcode, Opcode::Other(0x55));
        assert_eq! (subject.result_code_opt, None);
        assert_eq! (subject.lifetime, 0x78563412);
        assert_eq! (subject.client_ip_opt, Some (IpAddr::from_str ("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap()));
        assert_eq! (subject.epoch_time_opt, None);
        assert_eq! (subject.opcode_data.as_any().downcast_ref::<UnrecognizedData>().unwrap(), &UnrecognizedData::new());
        assert_eq! (subject.options.is_empty(), true);
    }

    #[test]
    fn from_works_for_unknown_request_with_ipv4() {
        let mut buffer: [u8; 24] = [
            0x12, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0x00, 0x00, 0x00, 0x00, // client IP address
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF,
            0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::new (&mut buffer).unwrap();

        assert_eq! (subject.client_ip_opt, Some (IpAddr::V4(Ipv4Addr::new (0x33, 0x22, 0x11, 0x00))));
    }

    #[test]
    fn from_works_for_map_request() {
        let mut buffer = [
            0x12, 0x01, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
            0xAA, 0x55, 0xAA, 0x55, // mapping nonce
            0xAA, 0x55, 0xAA, 0x55,
            0xAA, 0x55, 0xAA, 0x55,
            0x11, 0x00, 0x00, 0x00, // protocol, reserved
            0xC3, 0x50, 0xC3, 0x51, // internal port, external port
            0x00, 0x11, 0x22, 0x33, // suggested external IP address
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];

        let subject = PcpPacket::new (&mut buffer).unwrap();

        assert_eq! (subject.version, 0x12);
        assert_eq! (subject.direction, Direction::Request);
        assert_eq! (subject.opcode, Opcode::Map);
        assert_eq! (subject.result_code_opt, None);
        assert_eq! (subject.lifetime, 0x78563412);
        assert_eq! (subject.client_ip_opt, Some (IpAddr::from_str ("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap()));
        assert_eq! (subject.epoch_time_opt, None);
        let opcode_data = subject.opcode_data.as_any().downcast_ref::<MapOpcodeData>().unwrap();
        assert_eq! (opcode_data.mapping_nonce, [0xAAu8, 0x055, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55]);
        assert_eq! (opcode_data.protocol, Protocol::Udp);
        assert_eq! (opcode_data.internal_port, 50000);
        assert_eq! (opcode_data.external_port, 50001);
        assert_eq! (opcode_data.external_ip_address, IpAddr::from_str ("0011:2233:4455:6677:8899:aabb:ccdd:eeff").unwrap());
        assert_eq! (subject.options.is_empty(), true);
    }

    #[test]
    fn from_works_for_unknown_response() {
        let mut buffer: [u8; 24] = [
            0x13, 0xD5, 0x00, 0xAA, // version, direction, opcode, reserved, result code
            0x78, 0x56, 0x34, 0x12, // lifetime
            0x12, 0x34, 0x56, 0x78, // epoch time
            0xBB, 0xAA, 0x99, 0x88, // reserved
            0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::new (&mut buffer).unwrap();

        assert_eq! (subject.version, 0x13);
        assert_eq! (subject.direction, Direction::Response);
        assert_eq! (subject.opcode, Opcode::Other(0x55));
        assert_eq! (subject.result_code_opt, Some (0xAA));
        assert_eq! (subject.lifetime, 0x78563412);
        assert_eq! (subject.client_ip_opt, None);
        assert_eq! (subject.epoch_time_opt, Some (0x12345678));
        assert_eq! (subject.opcode_data.as_any().downcast_ref::<UnrecognizedData>().unwrap(), &UnrecognizedData::new());
        assert_eq! (subject.options.is_empty(), true);
    }

    #[test]
    fn short_buffer_causes_problems() {
        let mut buffer = [0u8; 23];

        let result = PcpPacket::new (&mut buffer).err().unwrap();

        assert_eq! (result, PcpParseError::ShortBuffer);
    }

    #[test]
    fn marshal_works_for_unknown_request_ipv6() {
        let mut buffer = [0u8; 24];
        buffer[1] = 0x7F; // opcode bits: Other, not Announce
        let mut subject = PcpPacket::new (&mut buffer).unwrap();
        subject.version = 0x12;
        subject.direction = Direction::Request;
        subject.opcode = Opcode::Other(0x55);
        subject.result_code_opt = None;
        subject.lifetime = 0x78563412;
        subject.client_ip_opt = Some (IpAddr::from_str ("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap());
        subject.epoch_time_opt = None;
        subject.opcode_data = Box::new (UnrecognizedData::new());
        subject.options = vec![];

        let result = subject.marshal().unwrap();

        assert_eq! (result, 24);
        let expected_buffer: [u8; 24] = [
            0x12, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        assert_eq! (buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_unknown_request_ipv4() {
        let mut buffer = [0u8; 24];
        buffer[1] = 0x7F; // opcode bits: Other, not Announce
        let mut subject = PcpPacket::new (&mut buffer).unwrap();
        subject.version = 0x12;
        subject.direction = Direction::Request;
        subject.opcode = Opcode::Other(0x55);
        subject.result_code_opt = None;
        subject.lifetime = 0x78563412;
        subject.client_ip_opt = Some (IpAddr::V4(Ipv4Addr::new (0x33, 0x22, 0x11, 0x00)));
        subject.epoch_time_opt = None;
        subject.opcode_data = Box::new (UnrecognizedData::new());
        subject.options = vec![];

        let result = subject.marshal().unwrap();

        assert_eq! (result, 24);
        let expected_buffer: [u8; 24] = [
            0x12, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0x00, 0x00, 0x00, 0x00, // client IP address
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF,
            0x33, 0x22, 0x11, 0x00,
        ];
        assert_eq! (buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_map_request() {
        let mut buffer = [0u8; 60];
        buffer[1] = 0x7F; // opcode bits: Other, not Announce
        let mut subject = PcpPacket::new (&mut buffer).unwrap();
        subject.version = 0x12;
        subject.direction = Direction::Request;
        subject.opcode = Opcode::Map;
        subject.result_code_opt = None;
        subject.lifetime = 0x78563412;
        subject.client_ip_opt = Some (IpAddr::from_str ("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap());
        subject.epoch_time_opt = None;
        subject.opcode_data = Box::new (MapOpcodeData {
            mapping_nonce: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
            protocol: Protocol::Udp,
            internal_port: 0x1234,
            external_port: 0x4321,
            external_ip_address: IpAddr::V4 (Ipv4Addr::new (0x44, 0x33, 0x22, 0x11)),
        });
        subject.options = vec![];

        let result = subject.marshal().unwrap();

        assert_eq! (result, 60);
        let expected_buffer: [u8; 60] = [
            0x12, 0x01, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
            0x11, 0x22, 0x33, 0x44, // mapping nonce
            0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC,
            0x11, 0x00, 0x00, 0x00, // protocol, reserved
            0x12, 0x34, 0x43, 0x21, // internal port, external port
            0x00, 0x00, 0x00, 0x00, // suggested external IP address
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF,
            0x44, 0x33, 0x22, 0x11,
        ];
        assert_eq! (buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_unknown_response() {
        let mut buffer = [0u8; 24];
        buffer[1] = 0x7F; // opcode bits: Other, not Announce
        let mut subject = PcpPacket::new (&mut buffer).unwrap();
        subject.version = 0x13;
        subject.direction = Direction::Response;
        subject.opcode = Opcode::Other(0x55);
        subject.result_code_opt = Some(0xAA);
        subject.lifetime = 0x78563412;
        subject.epoch_time_opt = Some (0x12345678);
        subject.client_ip_opt = None;
        subject.opcode_data = Box::new (UnrecognizedData::new());
        subject.options = vec![];

        let result = subject.marshal().unwrap();

        assert_eq! (result, 24);
        let expected_buffer: [u8; 24] = [
            0x13, 0xD5, 0x00, 0xAA, // version, direction, opcode, reserved, result code
            0x78, 0x56, 0x34, 0x12, // lifetime
            0x12, 0x34, 0x56, 0x78, // epoch time
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq! (buffer, expected_buffer);
    }

    #[test]
    fn direction_code_works() {
        assert_eq! (Direction::Request.code(), 0x00);
        assert_eq! (Direction::Response.code(), 0x80);
    }

    #[test]
    fn direction_from_works() {
        assert_eq! (Direction::from (0x00), Direction::Request);
        assert_eq! (Direction::from (0x7F), Direction::Request);
        assert_eq! (Direction::from (0x80), Direction::Response);
        assert_eq! (Direction::from (0xFF), Direction::Response);
    }

    #[test]
    fn opcode_code_works () {
        assert_eq! (Opcode::Announce.code(), 0);
        assert_eq! (Opcode::Map.code(), 1);
        assert_eq! (Opcode::Peer.code(), 2);
        assert_eq! (Opcode::Other(42).code(), 42);
        assert_eq! (Opcode::Other(255).code(), 127);
    }

    #[test]
    fn opcode_from_works () {
        assert_eq! (Opcode::from (0x00), Opcode::Announce);
        assert_eq! (Opcode::from (0x01), Opcode::Map);
        assert_eq! (Opcode::from (0x02), Opcode::Peer);
        assert_eq! (Opcode::from (0x03), Opcode::Other(3));
        assert_eq! (Opcode::from (0x7F), Opcode::Other(127));
        assert_eq! (Opcode::from (0x80), Opcode::Announce);
        assert_eq! (Opcode::from (0x81), Opcode::Map);
        assert_eq! (Opcode::from (0x82), Opcode::Peer);
        assert_eq! (Opcode::from (0x83), Opcode::Other(3));
        assert_eq! (Opcode::from (0xFF), Opcode::Other(127));
    }

    #[test]
    fn unrecognized_data_knows_its_length() {
        let subject = UnrecognizedData::new();

        let result = subject.len();

        assert_eq! (result, 0);
    }

    #[test]
    fn unrecognized_data_marshals() {
        let mut buf = [0x00u8; 0];
        let subject = UnrecognizedData::new();

        let result = subject.marshal(&mut buf);

        assert_eq! (result, Ok(()));
    }
}
