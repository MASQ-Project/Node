// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::{IpAddr, Ipv4Addr};
use std::any::Any;
use crate::protocols::utils::{u16_at, u16_into, OpcodeData, ipv6_addr_into, ipv6_addr_at, MarshalError, Direction, ParseError};
use crate::protocols::pcp::pcp_packet::PcpOpcodeData;

#[derive (Clone, PartialEq, Debug)]
pub enum Protocol {
    Udp,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(input: u8) -> Self {
        match input {
            17 => Protocol::Udp,
            x => Protocol::Other (x),
        }
    }
}

impl Protocol {
    pub fn code (&self) -> u8 {
        match self {
            Protocol::Udp => 17,
            Protocol::Other(x) => *x,
        }
    }
}

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
            unimplemented!()
        }
        for n in 0..12 {
            buf[n] = self.mapping_nonce[n]
        }
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

impl MapOpcodeData {
    pub fn new (buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 36 {
            unimplemented!()
        }
        let mut data = Self {
            mapping_nonce: [0u8; 12],
            protocol: Protocol::Udp,
            internal_port: 0,
            external_port: 0,
            external_ip_address: IpAddr::V4(Ipv4Addr::new (0, 0, 0, 0)),
        };
        for n in 0..12 {
            data.mapping_nonce[n] = buf[n]
        }
        data.protocol = Protocol::from (buf[12]);
        data.internal_port = u16_at (buf, 16);
        data.external_port = u16_at (buf, 18);
        data.external_ip_address = ipv6_addr_at(buf, 20);
        Ok (data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::utils::Direction;

    #[test]
    fn map_opcode_data_knows_its_length() {
        let subject = MapOpcodeData::new (&[0u8; 64]).unwrap();

        let result = subject.len(Direction::Request);

        assert_eq! (result, 36);
    }

    #[test]
    fn protocol_from_works() {
        assert_eq! (Protocol::from (17), Protocol::Udp);
        assert_eq! (Protocol::from (255), Protocol::Other (255));
    }

    #[test]
    fn protocol_code_works() {
        assert_eq! (Protocol::Udp.code(), 17);
        assert_eq! (Protocol::Other (255).code(), 255);
        assert_eq! (Protocol::Other (254).code(), 254);
    }
}