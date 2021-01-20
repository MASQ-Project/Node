// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::pcp::map_packet::MapOpcodeData;
use crate::protocols::utils::{
    ipv6_addr_at, ipv6_addr_into, u32_at, u32_into, Direction, MarshalError, OpcodeData, Packet,
    ParseError, UnrecognizedData,
};
use std::convert::{From, TryFrom};
use std::net::IpAddr;

#[derive(Clone, PartialEq, Debug)]
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
            x => Opcode::Other(x),
        }
    }
}

impl Opcode {
    pub fn code(&self) -> u8 {
        match self {
            Opcode::Announce => 0,
            Opcode::Map => 1,
            Opcode::Peer => 2,
            Opcode::Other(code) => code & 0x7F,
        }
    }

    pub fn parse_data(&self, buf: &[u8]) -> Result<Box<dyn PcpOpcodeData>, ParseError> {
        match self {
            Opcode::Announce => unimplemented!(),
            Opcode::Map => Ok(Box::new(MapOpcodeData::try_from(buf)?)),
            Opcode::Peer => unimplemented!(),
            Opcode::Other(_) => Ok(Box::new(UnrecognizedData::new())),
        }
    }
}

pub trait PcpOpcodeData: OpcodeData {}

impl PcpOpcodeData for UnrecognizedData {}

pub trait PcpOption {}

pub struct PcpPacket {
    pub direction: Direction,
    pub opcode: Opcode,
    pub result_code_opt: Option<u8>,
    pub lifetime: u32,
    pub client_ip_opt: Option<IpAddr>,
    pub epoch_time_opt: Option<u32>,
    pub opcode_data: Box<dyn PcpOpcodeData>,
    pub options: Vec<Box<dyn PcpOption>>,
}

impl Default for PcpPacket {
    fn default() -> Self {
        Self {
            direction: Direction::Request,
            opcode: Opcode::Other(127),
            result_code_opt: None,
            lifetime: 0,
            client_ip_opt: None,
            epoch_time_opt: None,
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        }
    }
}

impl Packet for PcpPacket {
    fn marshal(&self, buffer: &mut [u8]) -> Result<usize, MarshalError> {
        let required_len = 24 + self.opcode_data.len(self.direction);
        if buffer.len() < required_len {
            return Err(MarshalError::ShortBuffer(required_len, buffer.len()));
        }
        buffer[0] = 0x02; // version
        buffer[1] = self.direction.code() | self.opcode.code();
        buffer[2] = 0x00;
        match self.direction {
            Direction::Request => buffer[3] = 0x00,
            Direction::Response => buffer[3] = self.result_code_opt.unwrap_or(0x00),
        }
        u32_into(buffer, 4, self.lifetime);
        match self.direction {
            Direction::Request => match self.client_ip_opt {
                Some(ip_addr) => {
                    ipv6_addr_into(buffer, 8, &ip_addr);
                }
                None => {
                    u32_into(buffer, 8, 0);
                    u32_into(buffer, 12, 0);
                    u32_into(buffer, 16, 0);
                    u32_into(buffer, 20, 0);
                }
            },
            Direction::Response => {
                u32_into(buffer, 8, self.epoch_time_opt.unwrap_or(0));
                u32_into(buffer, 12, 0);
                u32_into(buffer, 16, 0);
                u32_into(buffer, 20, 0);
            }
        }
        self.opcode_data
            .marshal(self.direction, &mut buffer[24..])?;
        Ok(24 + self.opcode_data.len(self.direction))
    }
}

impl TryFrom<&[u8]> for PcpPacket {
    type Error = ParseError;

    fn try_from(buffer: &[u8]) -> Result<Self, ParseError> {
        let mut result = PcpPacket::default();
        if buffer.len() < 24 {
            return Err(ParseError::ShortBuffer(24, buffer.len()));
        }
        if buffer[0] != 0x02 {
            return Err(ParseError::WrongVersion(buffer[0]));
        }
        result.direction = Direction::from(buffer[1]);
        result.opcode = Opcode::from(buffer[1]);
        result.lifetime = u32_at(buffer, 4);
        match result.direction {
            Direction::Request => {
                result.client_ip_opt = Some(ipv6_addr_at(buffer, 8));
            }
            Direction::Response => {
                result.result_code_opt = Some(buffer[3]);
                result.epoch_time_opt = Some(u32_at(buffer, 8));
            }
        }
        result.opcode_data = result.opcode.parse_data(&buffer[24..])?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::pcp::map_packet::{MapOpcodeData, Protocol};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn from_works_for_unknown_request_with_ipv6() {
        let buffer: &[u8] = &[
            0x02, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::try_from(buffer).unwrap();

        assert_eq!(subject.direction, Direction::Request);
        assert_eq!(subject.opcode, Opcode::Other(0x55));
        assert_eq!(subject.result_code_opt, None);
        assert_eq!(subject.lifetime, 0x78563412);
        assert_eq!(
            subject.client_ip_opt,
            Some(IpAddr::from_str("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap())
        );
        assert_eq!(subject.epoch_time_opt, None);
        assert_eq!(
            subject
                .opcode_data
                .as_any()
                .downcast_ref::<UnrecognizedData>()
                .unwrap(),
            &UnrecognizedData::new()
        );
        assert_eq!(subject.options.is_empty(), true);
    }

    #[test]
    fn from_works_for_unknown_request_with_ipv4() {
        let buffer: &[u8] = &[
            0x02, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0x00, 0x00, 0x00, 0x00, // client IP address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::try_from(buffer).unwrap();

        assert_eq!(
            subject.client_ip_opt,
            Some(IpAddr::V4(Ipv4Addr::new(0x33, 0x22, 0x11, 0x00)))
        );
    }

    #[test]
    fn from_works_for_map_request() {
        let buffer: &[u8] = &[
            0x02, 0x01, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xAA, 0x55,
            0xAA, 0x55, // mapping nonce
            0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0x11, 0x00, 0x00,
            0x00, // protocol, reserved
            0xC3, 0x50, 0xC3, 0x51, // internal port, external port
            0x00, 0x11, 0x22, 0x33, // suggested external IP address
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];

        let subject = PcpPacket::try_from(buffer).unwrap();

        assert_eq!(subject.direction, Direction::Request);
        assert_eq!(subject.opcode, Opcode::Map);
        assert_eq!(subject.result_code_opt, None);
        assert_eq!(subject.lifetime, 0x78563412);
        assert_eq!(
            subject.client_ip_opt,
            Some(IpAddr::from_str("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap())
        );
        assert_eq!(subject.epoch_time_opt, None);
        let opcode_data = subject
            .opcode_data
            .as_any()
            .downcast_ref::<MapOpcodeData>()
            .unwrap();
        assert_eq!(
            opcode_data.mapping_nonce,
            [0xAAu8, 0x055, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55]
        );
        assert_eq!(opcode_data.protocol, Protocol::Udp);
        assert_eq!(opcode_data.internal_port, 50000);
        assert_eq!(opcode_data.external_port, 50001);
        assert_eq!(
            opcode_data.external_ip_address,
            IpAddr::from_str("0011:2233:4455:6677:8899:aabb:ccdd:eeff").unwrap()
        );
        assert_eq!(subject.options.is_empty(), true);
    }

    #[test]
    fn from_works_for_unknown_response() {
        let buffer: &[u8] = &[
            0x02, 0xD5, 0x00, 0xAA, // version, direction, opcode, reserved, result code
            0x78, 0x56, 0x34, 0x12, // lifetime
            0x12, 0x34, 0x56, 0x78, // epoch time
            0xBB, 0xAA, 0x99, 0x88, // reserved
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::try_from(buffer).unwrap();

        assert_eq!(subject.direction, Direction::Response);
        assert_eq!(subject.opcode, Opcode::Other(0x55));
        assert_eq!(subject.result_code_opt, Some(0xAA));
        assert_eq!(subject.lifetime, 0x78563412);
        assert_eq!(subject.client_ip_opt, None);
        assert_eq!(subject.epoch_time_opt, Some(0x12345678));
        assert_eq!(
            subject
                .opcode_data
                .as_any()
                .downcast_ref::<UnrecognizedData>()
                .unwrap(),
            &UnrecognizedData::new()
        );
        assert_eq!(subject.options.is_empty(), true);
    }

    #[test]
    fn short_buffer_causes_parse_problems() {
        let buffer: &[u8] = &[0u8; 23];

        let result = PcpPacket::try_from(buffer).err();

        assert_eq!(result, Some(ParseError::ShortBuffer(24, 23)));
    }

    #[test]
    fn wrong_version_causes_parse_problems() {
        let buffer: &[u8] = &[0x42u8; 24];

        let result = PcpPacket::try_from(buffer).err();

        assert_eq!(result, Some(ParseError::WrongVersion(0x42)));
    }

    #[test]
    fn marshal_works_for_unknown_request_ipv6() {
        let mut buffer = [0u8; 24];
        let subject = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Other(0x55),
            result_code_opt: None,
            lifetime: 0x78563412,
            client_ip_opt: Some(
                IpAddr::from_str("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap(),
            ),
            epoch_time_opt: None,
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        };

        let result = subject.marshal(&mut buffer).unwrap();

        assert_eq!(result, 24);
        let expected_buffer: [u8; 24] = [
            0x02, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ];
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_unknown_request_ipv4() {
        let mut buffer = [0u8; 24];
        let subject = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Other(0x55),
            result_code_opt: None,
            lifetime: 0x78563412,
            client_ip_opt: Some(IpAddr::V4(Ipv4Addr::new(0x33, 0x22, 0x11, 0x00))),
            epoch_time_opt: None,
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        };

        let result = subject.marshal(&mut buffer).unwrap();

        assert_eq!(result, 24);
        let expected_buffer: [u8; 24] = [
            0x02, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0x00, 0x00, 0x00, 0x00, // client IP address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x33, 0x22, 0x11, 0x00,
        ];
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_map_request() {
        let mut buffer = [0u8; 60];
        let subject = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Map,
            result_code_opt: None,
            lifetime: 0x78563412,
            client_ip_opt: Some(
                IpAddr::from_str("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap(),
            ),
            epoch_time_opt: None,
            opcode_data: Box::new(MapOpcodeData {
                mapping_nonce: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                ],
                protocol: Protocol::Udp,
                internal_port: 0x1234,
                external_port: 0x4321,
                external_ip_address: IpAddr::V4(Ipv4Addr::new(0x44, 0x33, 0x22, 0x11)),
            }),
            options: vec![],
        };

        let result = subject.marshal(&mut buffer).unwrap();

        assert_eq!(result, 60);
        let expected_buffer: [u8; 60] = [
            0x02, 0x01, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x11, 0x22,
            0x33, 0x44, // mapping nonce
            0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0x11, 0x00, 0x00,
            0x00, // protocol, reserved
            0x12, 0x34, 0x43, 0x21, // internal port, external port
            0x00, 0x00, 0x00, 0x00, // suggested external IP address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x44, 0x33, 0x22, 0x11,
        ];
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_unknown_response() {
        let mut buffer = [0u8; 24];
        let subject = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Other(0x55),
            result_code_opt: Some(0xAA),
            lifetime: 0x78563412,
            epoch_time_opt: Some(0x12345678),
            client_ip_opt: None,
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        };

        let result = subject.marshal(&mut buffer).unwrap();

        assert_eq!(result, 24);
        let expected_buffer: [u8; 24] = [
            0x02, 0xD5, 0x00, 0xAA, // version, direction, opcode, reserved, result code
            0x78, 0x56, 0x34, 0x12, // lifetime
            0x12, 0x34, 0x56, 0x78, // epoch time
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn short_buffer_causes_marshalling_problems() {
        let mut buffer = [0u8; 23];
        let subject = PcpPacket {
            direction: Direction::Request,
            opcode: Opcode::Other(127),
            result_code_opt: None,
            lifetime: 0,
            client_ip_opt: None,
            epoch_time_opt: None,
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        };

        let result = subject.marshal(&mut buffer);

        assert_eq!(result, Err(MarshalError::ShortBuffer(24, 23)));
    }

    #[test]
    fn opcode_code_works() {
        assert_eq!(Opcode::Announce.code(), 0);
        assert_eq!(Opcode::Map.code(), 1);
        assert_eq!(Opcode::Peer.code(), 2);
        assert_eq!(Opcode::Other(42).code(), 42);
        assert_eq!(Opcode::Other(255).code(), 127);
    }

    #[test]
    fn opcode_from_works() {
        assert_eq!(Opcode::from(0x00), Opcode::Announce);
        assert_eq!(Opcode::from(0x01), Opcode::Map);
        assert_eq!(Opcode::from(0x02), Opcode::Peer);
        assert_eq!(Opcode::from(0x03), Opcode::Other(3));
        assert_eq!(Opcode::from(0x7F), Opcode::Other(127));
        assert_eq!(Opcode::from(0x80), Opcode::Announce);
        assert_eq!(Opcode::from(0x81), Opcode::Map);
        assert_eq!(Opcode::from(0x82), Opcode::Peer);
        assert_eq!(Opcode::from(0x83), Opcode::Other(3));
        assert_eq!(Opcode::from(0xFF), Opcode::Other(127));
    }
}
