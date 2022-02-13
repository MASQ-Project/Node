// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::pcp::map_packet::MapOpcodeData;
use crate::protocols::utils::{
    ipv6_addr_at, ipv6_addr_into, u32_at, u32_into, Direction, MarshalError, OpcodeData, Packet,
    ParseError, UnrecognizedData,
};
use std::convert::{From, TryFrom};
use std::fmt::Debug;
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
            Opcode::Announce => Ok(Box::new(UnrecognizedData::new())),
            Opcode::Map => Ok(Box::new(MapOpcodeData::try_from(buf)?)),
            Opcode::Peer => Err(ParseError::UnexpectedOpcode("Peer".to_string())),
            Opcode::Other(_) => Ok(Box::new(UnrecognizedData::new())),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ResultCode {
    Success,
    UnsuppVersion,
    NotAuthorized,
    MalformedRequest,
    UnsuppOpcode,
    UnsuppOption,
    MalformedOption,
    NetworkFailure,
    NoResources,
    UnsuppProtocol,
    UserExQuota,
    CannotProvideExternal,
    AddressMismatch,
    ExcessiveRemotePeers,
    Other(u8),
}

impl From<u8> for ResultCode {
    fn from(input: u8) -> Self {
        match input {
            0 => ResultCode::Success,
            1 => ResultCode::UnsuppVersion,
            2 => ResultCode::NotAuthorized,
            3 => ResultCode::MalformedRequest,
            4 => ResultCode::UnsuppOpcode,
            5 => ResultCode::UnsuppOption,
            6 => ResultCode::MalformedOption,
            7 => ResultCode::NetworkFailure,
            8 => ResultCode::NoResources,
            9 => ResultCode::UnsuppProtocol,
            10 => ResultCode::UserExQuota,
            11 => ResultCode::CannotProvideExternal,
            12 => ResultCode::AddressMismatch,
            13 => ResultCode::ExcessiveRemotePeers,
            code => ResultCode::Other(code),
        }
    }
}

impl ResultCode {
    pub fn code(&self) -> u8 {
        match self {
            ResultCode::Success => 0,
            ResultCode::UnsuppVersion => 1,
            ResultCode::NotAuthorized => 2,
            ResultCode::MalformedRequest => 3,
            ResultCode::UnsuppOpcode => 4,
            ResultCode::UnsuppOption => 5,
            ResultCode::MalformedOption => 6,
            ResultCode::NetworkFailure => 7,
            ResultCode::NoResources => 8,
            ResultCode::UnsuppProtocol => 9,
            ResultCode::UserExQuota => 10,
            ResultCode::CannotProvideExternal => 11,
            ResultCode::AddressMismatch => 12,
            ResultCode::ExcessiveRemotePeers => 13,
            ResultCode::Other(code) => *code,
        }
    }

    pub fn is_permanent(&self) -> bool {
        match self {
            ResultCode::Success => false,
            ResultCode::UnsuppVersion => true,
            ResultCode::NotAuthorized => true,
            ResultCode::MalformedRequest => true,
            ResultCode::UnsuppOpcode => true,
            ResultCode::UnsuppOption => true,
            ResultCode::MalformedOption => true,
            ResultCode::NetworkFailure => false,
            ResultCode::NoResources => false,
            ResultCode::UnsuppProtocol => true,
            ResultCode::UserExQuota => false,
            ResultCode::CannotProvideExternal => false,
            ResultCode::AddressMismatch => true,
            ResultCode::ExcessiveRemotePeers => true,
            ResultCode::Other(_) => true,
        }
    }
}

pub trait PcpOpcodeData: OpcodeData + Debug {}

impl PcpOpcodeData for UnrecognizedData {}

pub trait PcpOption: Debug {}

#[derive(Debug)]
pub struct PcpPacket {
    pub direction: Direction,
    pub opcode: Opcode,
    pub result_code_opt: Option<ResultCode>,
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
            Direction::Response => {
                buffer[3] = self
                    .result_code_opt
                    .unwrap_or(ResultCode::Other(0xFF))
                    .code()
            }
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
                result.result_code_opt = Some(ResultCode::from(buffer[3]));
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
    fn from_works_for_announce_packet() {
        let buffer: &[u8] = &[
            0x02, 0x80, 0x00, 0x00, // version, direction, opcode, reserved, result code
            0x78, 0x56, 0x34, 0x12, // lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // epoch time
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
        ];

        let subject = PcpPacket::try_from(buffer).unwrap();

        assert_eq!(subject.direction, Direction::Response);
        assert_eq!(subject.opcode, Opcode::Announce);
        assert_eq!(subject.result_code_opt, Some(ResultCode::Success));
        assert_eq!(subject.lifetime, 0x78563412);
        assert_eq!(subject.epoch_time_opt, Some(0xFFEEDDCC));
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
        assert_eq!(subject.result_code_opt, Some(ResultCode::Other(0xAA)));
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
    fn marshal_works_for_announce() {
        let mut buffer = [0u8; 24];
        let subject = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Announce,
            result_code_opt: Some(ResultCode::Success),
            lifetime: 0x78563412,
            client_ip_opt: None,
            epoch_time_opt: Some(0xFFEEDDCC),
            opcode_data: Box::new(UnrecognizedData::new()),
            options: vec![],
        };

        let result = subject.marshal(&mut buffer).unwrap();

        assert_eq!(result, 24);
        let expected_buffer: [u8; 24] = [
            0x02, 0x80, 0x00, 0x00, // version, direction, opcode, reserved, result code
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // epoch time
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
        ];
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn marshal_works_for_unknown_response() {
        let mut buffer = [0u8; 24];
        let subject = PcpPacket {
            direction: Direction::Response,
            opcode: Opcode::Other(0x55),
            result_code_opt: Some(ResultCode::Other(0xAA)),
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
    fn peer_opcode_is_future_enhancement() {
        let result = Opcode::Peer.parse_data(&[]).err().unwrap();

        assert_eq!(result, ParseError::UnexpectedOpcode("Peer".to_string()));
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

    #[test]
    fn result_code_code_works() {
        assert_eq!(ResultCode::Success.code(), 0);
        assert_eq!(ResultCode::UnsuppVersion.code(), 1);
        assert_eq!(ResultCode::NotAuthorized.code(), 2);
        assert_eq!(ResultCode::MalformedRequest.code(), 3);
        assert_eq!(ResultCode::UnsuppOpcode.code(), 4);
        assert_eq!(ResultCode::UnsuppOption.code(), 5);
        assert_eq!(ResultCode::MalformedOption.code(), 6);
        assert_eq!(ResultCode::NetworkFailure.code(), 7);
        assert_eq!(ResultCode::NoResources.code(), 8);
        assert_eq!(ResultCode::UnsuppProtocol.code(), 9);
        assert_eq!(ResultCode::UserExQuota.code(), 10);
        assert_eq!(ResultCode::CannotProvideExternal.code(), 11);
        assert_eq!(ResultCode::AddressMismatch.code(), 12);
        assert_eq!(ResultCode::ExcessiveRemotePeers.code(), 13);
        for code in 14..=u8::MAX {
            assert_eq!(ResultCode::Other(code).code(), code);
        }
    }

    #[test]
    fn result_code_from_works() {
        assert_eq!(ResultCode::from(0), ResultCode::Success);
        assert_eq!(ResultCode::from(1), ResultCode::UnsuppVersion);
        assert_eq!(ResultCode::from(2), ResultCode::NotAuthorized);
        assert_eq!(ResultCode::from(3), ResultCode::MalformedRequest);
        assert_eq!(ResultCode::from(4), ResultCode::UnsuppOpcode);
        assert_eq!(ResultCode::from(5), ResultCode::UnsuppOption);
        assert_eq!(ResultCode::from(6), ResultCode::MalformedOption);
        assert_eq!(ResultCode::from(7), ResultCode::NetworkFailure);
        assert_eq!(ResultCode::from(8), ResultCode::NoResources);
        assert_eq!(ResultCode::from(9), ResultCode::UnsuppProtocol);
        assert_eq!(ResultCode::from(10), ResultCode::UserExQuota);
        assert_eq!(ResultCode::from(11), ResultCode::CannotProvideExternal);
        assert_eq!(ResultCode::from(12), ResultCode::AddressMismatch);
        assert_eq!(ResultCode::from(13), ResultCode::ExcessiveRemotePeers);
        for code in 14..=u8::MAX {
            assert_eq!(ResultCode::from(code), ResultCode::Other(code));
        }
    }

    #[test]
    fn result_code_is_permanent_works() {
        assert_eq!(ResultCode::Success.is_permanent(), false);
        assert_eq!(ResultCode::UnsuppVersion.is_permanent(), true);
        assert_eq!(ResultCode::NotAuthorized.is_permanent(), true);
        assert_eq!(ResultCode::MalformedRequest.is_permanent(), true);
        assert_eq!(ResultCode::UnsuppOpcode.is_permanent(), true);
        assert_eq!(ResultCode::UnsuppOption.is_permanent(), true);
        assert_eq!(ResultCode::MalformedOption.is_permanent(), true);
        assert_eq!(ResultCode::NetworkFailure.is_permanent(), false);
        assert_eq!(ResultCode::NoResources.is_permanent(), false);
        assert_eq!(ResultCode::UnsuppProtocol.is_permanent(), true);
        assert_eq!(ResultCode::UserExQuota.is_permanent(), false);
        assert_eq!(ResultCode::CannotProvideExternal.is_permanent(), false);
        assert_eq!(ResultCode::AddressMismatch.is_permanent(), true);
        assert_eq!(ResultCode::ExcessiveRemotePeers.is_permanent(), true);
        for code in 14..=u8::MAX {
            assert_eq!(ResultCode::Other(code).is_permanent(), true);
        }
    }
}
