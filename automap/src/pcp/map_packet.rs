// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::{IpAddr, Ipv4Addr};
use crate::pcp::pcp_packet::{OpcodeData, ip_addr_at, PcpMarshalError, u16_into, ip_addr_into};
use std::any::Any;
use crate::pcp::pcp_packet::u16_at;

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
    fn marshal(&self, buf: &mut [u8]) -> Result<(), PcpMarshalError> {
        if buf.len() < self.len() {
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
        ip_addr_into(buf, 20, &self.external_ip_address);
        Ok(())
    }

    fn len(&self) -> usize {
        36
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl MapOpcodeData {
    pub fn new (buf: &[u8]) -> Self {
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
        data.external_ip_address = ip_addr_at(buf, 20);
        data
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_opcode_data_knows_its_length() {
        let subject = MapOpcodeData::new (&[0u8; 64]);

        let result = subject.len();

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