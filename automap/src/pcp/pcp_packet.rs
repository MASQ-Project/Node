// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::convert::From;
use std::net::{IpAddr, Ipv6Addr};
use std::any::Any;

#[derive (Clone, PartialEq, Debug)]
pub enum Direction {
    Request,
    Response,
}

#[derive (Clone, PartialEq, Debug)]
pub enum Opcode {
    // Announce is 0, Map is 1, Peer is 2
    Map,
    Other(u8),
}

impl From<u8> for Opcode {
    fn from(input: u8) -> Self {
        match input {
            _ => Opcode::Other (input)
        }
    }
}

pub trait OpcodeData {
    fn as_any(&self) -> &dyn Any;
}

#[derive (PartialEq, Debug)]
struct UnrecognizedData {

}

impl OpcodeData for UnrecognizedData {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UnrecognizedData {
    fn new () -> UnrecognizedData {
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
    pub fn new(input: &'a mut dyn AsMut<[u8]>) -> Result<Self, PcpParseError> {
        let mut result = PcpPacket {
            buf: input.as_mut(),
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
        result.direction = match result.buf[1] & 0x80 {
            0 => Direction::Request,
            _ => Direction::Response,
        };
        result.opcode = Opcode::from (result.buf[1] & 0x7F);
        result.lifetime = u32_at (result.buf, 4);
        match result.direction {
            Direction::Request => {
                result.client_ip_opt = Some (IpAddr::V6(Ipv6Addr::new (
                    u16_at (result.buf, 8),
                    u16_at (result.buf, 10),
                    u16_at (result.buf, 12),
                    u16_at (result.buf, 14),
                    u16_at (result.buf, 16),
                    u16_at (result.buf, 18),
                    u16_at (result.buf, 20),
                    u16_at (result.buf, 22),
                )));
            },
            Direction::Response => {
                result.result_code_opt = Some (result.buf[3]);
                result.epoch_time_opt = Some (u32_at (result.buf, 8));
            },
        }
        Ok(result)
    }

    pub fn marshal (&mut self) -> Result<usize, PcpMarshalError> {
        self.buf[0] = self.version;
        self.buf[1] = self.direction.code() & self.opcode.code();
        self.buf[2] = 0x00;
        match self.direction {
            Direction::Request => self.buf[3] = 0x00,
            Direction::Response => self.buf[4] = unimplemented!(), //self.result_code_opt.unwrap_or (0x00),
        }
        u32_into (self.buf, 4, self.lifetime);
        match self.client_ip_opt {
            Some (ip_addr) => {
                ip_addr.
            },
            None => {
                u32_into (self.buf, 8, 0);
                u32_into (self.buf, 12, 0);
                u32_into (self.buf, 16, 0);
                u32_into (self.buf, 20, 0);
            }
        }
        Ok(24)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn from_works_for_unknown_request() {
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
    fn marshal_works_for_unknown_request() {
        let mut buffer = [0u8; 24];
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
}
