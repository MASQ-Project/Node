// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::pmp::pmp_packet::PmpOpcodeData;
use crate::protocols::utils::{
    ipv4_addr_into, u32_at, u32_into, Direction, MarshalError, OpcodeData, ParseError,
};
use std::any::Any;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq)]
pub struct GetOpcodeData {
    pub epoch_opt: Option<u32>,
    pub external_ip_address_opt: Option<Ipv4Addr>,
}

impl OpcodeData for GetOpcodeData {
    fn marshal(&self, direction: Direction, buf: &mut [u8]) -> Result<(), MarshalError> {
        match direction {
            Direction::Request => Ok(()),
            Direction::Response => {
                if buf.len() < 8 {
                    return Err(MarshalError::ShortBuffer(8, buf.len()));
                }
                u32_into(buf, 0, self.epoch_opt.unwrap_or(0));
                ipv4_addr_into(
                    buf,
                    4,
                    &self
                        .external_ip_address_opt
                        .unwrap_or_else(||Ipv4Addr::new(0, 0, 0, 0)),
                );
                Ok(())
            }
        }
    }

    fn len(&self, direction: Direction) -> usize {
        match direction {
            Direction::Request => 0,
            Direction::Response => 8,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PmpOpcodeData for GetOpcodeData {}

impl Default for GetOpcodeData {
    fn default() -> Self {
        Self {
            epoch_opt: None,
            external_ip_address_opt: None,
        }
    }
}

impl TryFrom<(Direction, &[u8])> for GetOpcodeData {
    type Error = ParseError;

    fn try_from(pair: (Direction, &[u8])) -> Result<Self, Self::Error> {
        let (direction, buffer) = pair;
        match direction {
            Direction::Request => Ok(Self {
                epoch_opt: None,
                external_ip_address_opt: None,
            }),
            Direction::Response => {
                if buffer.len() < 8 {
                    return Err(ParseError::ShortBuffer(8, buffer.len()));
                }
                Ok(Self {
                    epoch_opt: Some(u32_at(buffer, 0)),
                    external_ip_address_opt: Some(Ipv4Addr::new(
                        buffer[4], buffer[5], buffer[6], buffer[7],
                    )),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_marshal_populated_response() {
        let subject = GetOpcodeData {
            epoch_opt: Some(0x11223344),
            external_ip_address_opt: Some(Ipv4Addr::new(0x44, 0x33, 0x22, 0x11)),
        };
        let mut buf = [0xFFu8; 8];

        subject.marshal(Direction::Response, &mut buf).unwrap();

        assert_eq!(&buf, &[0x11u8, 0x22, 0x33, 0x44, 0x44, 0x33, 0x22, 0x11,]);
    }

    #[test]
    fn can_marshal_unpopulated_response() {
        let subject = GetOpcodeData {
            epoch_opt: None,
            external_ip_address_opt: None,
        };
        let mut buf = [0xFFu8; 8];

        subject.marshal(Direction::Response, &mut buf).unwrap();

        assert_eq!(&buf, &[0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]);
    }

    #[test]
    fn marshal_complains_about_short_buffer() {
        let subject = GetOpcodeData {
            epoch_opt: None,
            external_ip_address_opt: None,
        };
        let mut buf = [0xFFu8; 7];

        let result = subject.marshal(Direction::Response, &mut buf);

        assert_eq!(result, Err(MarshalError::ShortBuffer(8, 7)));
    }

    #[test]
    fn knows_lengths() {
        let subject = GetOpcodeData {
            epoch_opt: None,
            external_ip_address_opt: None,
        };

        assert_eq!(subject.len(Direction::Request), 0);
        assert_eq!(subject.len(Direction::Response), 8);
    }

    #[test]
    fn new_complains_about_short_buffer() {
        let buf: &[u8] = &[0x00u8; 7];

        let result = GetOpcodeData::try_from((Direction::Response, buf)).err();

        assert_eq!(result, Some(ParseError::ShortBuffer(8, 7)));
    }
}
