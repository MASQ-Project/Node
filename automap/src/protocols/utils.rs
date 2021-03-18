// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Direction {
    Request,
    Response,
}

impl From<u8> for Direction {
    fn from(input: u8) -> Self {
        if (input & 0x80) > 0 {
            Direction::Response
        } else {
            Direction::Request
        }
    }
}

impl Direction {
    pub fn code(&self) -> u8 {
        match self {
            Direction::Request => 0x00,
            Direction::Response => 0x80,
        }
    }
}

pub trait OpcodeData {
    fn marshal(&self, direction: Direction, buf: &mut [u8]) -> Result<(), MarshalError>;
    fn len(&self, direction: Direction) -> usize;
    fn as_any(&self) -> &dyn Any;
}

#[derive(PartialEq, Debug)]
pub struct UnrecognizedData {}

impl OpcodeData for UnrecognizedData {
    fn marshal(&self, _direction: Direction, _buf: &mut [u8]) -> Result<(), MarshalError> {
        Ok(())
    }

    fn len(&self, _direction: Direction) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[allow(clippy::new_without_default)]
impl UnrecognizedData {
    pub fn new() -> UnrecognizedData {
        UnrecognizedData {}
    }
}

pub trait Packet {
    fn marshal(&self, buffer: &mut [u8]) -> Result<usize, MarshalError>;
}

#[derive(Clone, PartialEq, Debug)]
pub enum ParseError {
    WrongVersion(u8),
    ShortBuffer(usize, usize),
}

#[derive(Clone, PartialEq, Debug)]
pub enum MarshalError {
    ShortBuffer(usize, usize),
}

pub fn u32_at(buf: &[u8], offset: usize) -> u32 {
    ((buf[offset] as u32) << 24)
        + ((buf[offset + 1] as u32) << 16)
        + ((buf[offset + 2] as u32) << 8)
        + (buf[offset + 3] as u32)
}

pub fn u32_into(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = (value >> 24) as u8;
    buf[offset + 1] = ((value >> 16) & 0xFF) as u8;
    buf[offset + 2] = ((value >> 8) & 0xFF) as u8;
    buf[offset + 3] = (value & 0xFF) as u8;
}

pub fn u16_at(buf: &[u8], offset: usize) -> u16 {
    ((buf[offset] as u16) << 8) + (buf[offset + 1] as u16)
}

pub fn u16_into(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset] = (value >> 8) as u8;
    buf[offset + 1] = (value & 0xFF) as u8;
}

pub fn ipv4_addr_at(buf: &[u8], offset: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ))
}

pub fn ipv6_addr_at(buf: &[u8], offset: usize) -> IpAddr {
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
        Some(ipv4_addr) => IpAddr::V4(ipv4_addr),
        None => IpAddr::V6(ipv6_addr),
    }
}

pub fn ipv6_addr_into(buf: &mut [u8], offset: usize, value: &IpAddr) {
    let ipv6_addr = match value {
        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        IpAddr::V6(addr) => *addr,
    };
    let octets = ipv6_addr.octets();
    buf[offset..(16 + offset)].clone_from_slice(&octets[..16]);
}

pub fn ipv4_addr_into(buf: &mut [u8], offset: usize, value: &Ipv4Addr) {
    let octets = value.octets();
    buf[offset..(4 + offset)].clone_from_slice(&octets[..4]);
}
pub const MAIN_HEADER: &str = "\
+---------------------------------------------------------------------------------+
|                 3 protocol tests are finishing in a few seconds                 |
+---------------------------------------------------------------------------------+";
pub const PMP_HEADER: &str = "Summary of testing PMP protocol on your device:";
pub const PCP_HEADER: &str = "Summary of testing PCP protocol on your device:";
pub const IGDP_HEADER: &str = "Summary of testing IGDP/UPnP on your device:";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_code_works() {
        assert_eq!(Direction::Request.code(), 0x00);
        assert_eq!(Direction::Response.code(), 0x80);
    }

    #[test]
    fn direction_from_works() {
        assert_eq!(Direction::from(0x00), Direction::Request);
        assert_eq!(Direction::from(0x7F), Direction::Request);
        assert_eq!(Direction::from(0x80), Direction::Response);
        assert_eq!(Direction::from(0xFF), Direction::Response);
    }

    #[test]
    fn unrecognized_data_knows_its_length() {
        let subject = UnrecognizedData::new();

        let result = subject.len(Direction::Request);

        assert_eq!(result, 0);
    }

    #[test]
    fn unrecognized_data_marshals() {
        let mut buf = [0x00u8; 0];
        let subject = UnrecognizedData::new();

        let result = subject.marshal(Direction::Request, &mut buf);

        assert_eq!(result, Ok(()));
    }
}
