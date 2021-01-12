// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::convert::From;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

}

pub struct PcpPacket<'a> {
    buf: &'a [u8],
    pub version: u8,
    pub direction: Direction,
    pub opcode: Opcode,
    pub result_code: Option<u8>,
    pub lifetime: u32,
    pub client_ip: IpAddr,
    pub epoch_time: Option<u32>,
    pub opcode_data: Box<dyn OpcodeData>,
    pub options: Vec<Box<dyn PcpOption>>,
}

impl<'a> PcpPacket<'a> {
    pub fn new(input: &'a dyn AsRef<[u8]>) -> Result<Self, PcpParseError> {
        let mut result = PcpPacket {
            buf: input.as_ref(),
            version: 0,
            direction: Direction::Request,
            opcode: Opcode::Other (0),
            result_code: None,
            lifetime: 0,
            client_ip: IpAddr::V4(Ipv4Addr::new (127, 0, 0, 1)),
            epoch_time: None,
            opcode_data: Box::new (UnrecognizedData::new()),
            options: vec![],
        };
        if result.buf.len() < 24 {
            unimplemented!("Test-drive me!")
        }
        result.version = result.buf[0];
        result.direction = match result.buf[1] & 0x80 {
            0 => Direction::Request,
            _ => unimplemented!(),
        };
        result.opcode = Opcode::from (result.buf[1] & 0x7F);
        result.lifetime = u32_at (result.buf, 4);
        result.client_ip = IpAddr::V6(Ipv6Addr::new (
            u16_at (result.buf, 8),
            u16_at (result.buf, 10),
            u16_at (result.buf, 12),
            u16_at (result.buf, 14),
            u16_at (result.buf, 16),
            u16_at (result.buf, 18),
            u16_at (result.buf, 20),
            u16_at (result.buf, 22),
        ));
        Ok(result)
    }
}

pub fn u32_at (buf: &[u8], offset: usize) -> u32 {
    ((buf[offset] as u32) << 24) +
        ((buf[offset + 1] as u32) << 16) +
        ((buf[offset + 2] as u32) << 8) +
        (buf[offset + 3] as u32)
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
        let buffer: [u8; 24] = [
            0x12, 0x55, 0x00, 0x00, // version, direction, opcode, reserved
            0x78, 0x56, 0x34, 0x12, // requested lifetime
            0xFF, 0xEE, 0xDD, 0xCC, // client IP address
            0xBB, 0xAA, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];

        let subject = PcpPacket::new (&buffer).unwrap();

        assert_eq! (subject.version, 0x12);
        assert_eq! (subject.direction, Direction::Request);
        assert_eq! (subject.opcode, Opcode::Other(0x55));
        assert_eq! (subject.lifetime, 0x78563412);
        assert_eq! (subject.client_ip, IpAddr::from_str ("ffee:ddcc:bbaa:9988:7766:5544:3322:1100").unwrap());
        assert_eq! (subject.epoch_time, None);
        assert_eq! (subject.opcode_data.as_any().downcast_ref::<UnrecognizedData>().unwrap(), &UnrecognizedData::new());
        assert_eq! (subject.options.is_empty(), true);
    }
}
