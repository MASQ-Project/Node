// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::pcp::pcp_packet::PcpOpcodeData;
use crate::protocols::utils::{
    ipv6_addr_at, ipv6_addr_into, u16_at, u16_into, Direction, MarshalError, OpcodeData, ParseError,
};
use std::any::Any;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, PartialEq, Debug)]
pub enum Protocol {
    Udp,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(input: u8) -> Self {
        match input {
            17 => Protocol::Udp,
            x => Protocol::Other(x),
        }
    }
}

impl Protocol {
    pub fn code(&self) -> u8 {
        match self {
            Protocol::Udp => 17,
            Protocol::Other(x) => *x,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct MapOpcodeData {
    pub mapping_nonce: [u8; 12],
    pub protocol: Protocol,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_ip_address: IpAddr,
}

impl OpcodeData for MapOpcodeData {
    fn marshal(&self, direction: Direction, buf: &mut [u8]) -> Result<(), MarshalError> {
        if buf.len() < self.len(direction) {
            return Err(MarshalError::ShortBuffer(self.len(direction), buf.len()));
        }

        buf[..12].clone_from_slice(&self.mapping_nonce[..12]);

        buf[12] = self.protocol.code();
        buf[13] = 0x00;
        buf[14] = 0x00;
        buf[15] = 0x00;
        u16_into(buf, 16, self.internal_port);
        u16_into(buf, 18, self.external_port);
        ipv6_addr_into(buf, 20, &self.external_ip_address);
        Ok(())
    }

    fn len(&self, _: Direction) -> usize {
        36
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PcpOpcodeData for MapOpcodeData {}

impl Default for MapOpcodeData {
    fn default() -> Self {
        Self {
            mapping_nonce: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            protocol: Protocol::Other(127),
            internal_port: 0,
            external_port: 0,
            external_ip_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl TryFrom<&[u8]> for MapOpcodeData {
    type Error = ParseError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let mut data = MapOpcodeData::default();
        if buffer.len() < data.len(Direction::Request) {
            return Err(ParseError::ShortBuffer(
                data.len(Direction::Request),
                buffer.len(),
            ));
        }
        data.mapping_nonce[..12].clone_from_slice(&buffer[..12]);

        data.protocol = Protocol::from(buffer[12]);
        data.internal_port = u16_at(buffer, 16);
        data.external_port = u16_at(buffer, 18);
        data.external_ip_address = ipv6_addr_at(buffer, 20);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::utils::Direction;

    #[test]
    fn map_opcode_data_knows_its_length() {
        let buffer: &[u8] = &[0u8; 64];
        let subject = MapOpcodeData::try_from(buffer).unwrap();

        let result = subject.len(Direction::Request);

        assert_eq!(result, 36);
    }

    #[test]
    fn short_buffer_causes_parse_problem() {
        let buffer: &[u8] = &[0x00u8; 35];

        let result = MapOpcodeData::try_from(buffer).err();

        assert_eq!(result, Some(ParseError::ShortBuffer(36, 35)));
    }

    #[test]
    fn short_buffer_causes_marshal_problem() {
        let mut buffer = [0x00u8; 35];
        let subject = MapOpcodeData {
            mapping_nonce: [0; 12],
            protocol: Protocol::Udp,
            internal_port: 0,
            external_port: 0,
            external_ip_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        };

        let result = subject.marshal(Direction::Response, &mut buffer);

        assert_eq!(result, Err(MarshalError::ShortBuffer(36, 35)));
    }

    #[test]
    fn protocol_from_works() {
        assert_eq!(Protocol::from(17), Protocol::Udp);
        assert_eq!(Protocol::from(255), Protocol::Other(255));
    }

    #[test]
    fn protocol_code_works() {
        assert_eq!(Protocol::Udp.code(), 17);
        assert_eq!(Protocol::Other(255).code(), 255);
        assert_eq!(Protocol::Other(254).code(), 254);
    }
}
