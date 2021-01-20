// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::pmp::pmp_packet::PmpOpcodeData;
use crate::protocols::utils::{
    u16_at, u16_into, u32_at, u32_into, Direction, MarshalError, OpcodeData, ParseError,
};
use std::any::Any;
use std::convert::TryFrom;

#[derive(Clone, PartialEq, Debug)]
pub struct MapOpcodeData {
    pub epoch_opt: Option<u32>,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime: u32,
}

impl OpcodeData for MapOpcodeData {
    fn marshal(&self, direction: Direction, buf: &mut [u8]) -> Result<(), MarshalError> {
        if buf.len() < self.len(direction) {
            return Err(MarshalError::ShortBuffer(self.len(direction), buf.len()));
        }
        let mut position = 0;
        match direction {
            Direction::Request => {
                u16_into(buf, 0, 0x00);
                position += 2;
            }
            Direction::Response => {
                u32_into(buf, position, self.epoch_opt.unwrap_or(0));
                position += 4;
            }
        }
        u16_into(buf, position, self.internal_port);
        u16_into(buf, position + 2, self.external_port);
        u32_into(buf, position + 4, self.lifetime);
        Ok(())
    }

    fn len(&self, direction: Direction) -> usize {
        match direction {
            Direction::Request => 10,
            Direction::Response => 12,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PmpOpcodeData for MapOpcodeData {}

impl Default for MapOpcodeData {
    fn default() -> Self {
        Self {
            epoch_opt: None,
            internal_port: 0,
            external_port: 0,
            lifetime: 0,
        }
    }
}

impl TryFrom<(Direction, &[u8])> for MapOpcodeData {
    type Error = ParseError;

    fn try_from(pair: (Direction, &[u8])) -> Result<Self, Self::Error> {
        let (direction, buffer) = pair;
        let mut result = MapOpcodeData::default();
        if buffer.len() < result.len(direction) {
            return Err(ParseError::ShortBuffer(result.len(direction), buffer.len()));
        }
        let mut position = 0;
        match direction {
            Direction::Request => {
                position += 2;
            }
            Direction::Response => {
                result.epoch_opt = Some(u32_at(buffer, position));
                position += 4;
            }
        }
        result.internal_port = u16_at(buffer, position);
        result.external_port = u16_at(buffer, position + 2);
        result.lifetime = u32_at(buffer, position + 4);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::utils::ParseError;

    #[test]
    fn marshal_request_complains_about_short_buffer() {
        let mut buffer = [0u8; 9];
        let subject = MapOpcodeData {
            epoch_opt: None,
            internal_port: 1234,
            external_port: 4321,
            lifetime: 12344321,
        };

        let result = subject.marshal(Direction::Request, &mut buffer).err();

        assert_eq!(result, Some(MarshalError::ShortBuffer(10, 9)));
    }

    #[test]
    fn marshal_response_complains_about_short_buffer() {
        let mut buffer = [0u8; 11];
        let subject = MapOpcodeData {
            epoch_opt: Some(43211234),
            internal_port: 1234,
            external_port: 4321,
            lifetime: 12344321,
        };

        let result = subject.marshal(Direction::Response, &mut buffer).err();

        assert_eq!(result, Some(MarshalError::ShortBuffer(12, 11)));
    }

    #[test]
    fn marshal_request_works() {
        let mut buffer = [0u8; 10];
        let subject = MapOpcodeData {
            epoch_opt: None,
            internal_port: 0x1234,
            external_port: 0x4321,
            lifetime: 0x12344321,
        };

        subject.marshal(Direction::Request, &mut buffer).unwrap();

        assert_eq!(
            buffer,
            [
                0x00u8, 0x00, // reserved
                0x12, 0x34, 0x43, 0x21, // internal port, external port
                0x12, 0x34, 0x43, 0x21, // lifetime
            ]
        );
    }

    #[test]
    fn marshal_response_works() {
        let mut buffer = [0u8; 12];
        let subject = MapOpcodeData {
            epoch_opt: Some(0x43211234),
            internal_port: 0x1234,
            external_port: 0x4321,
            lifetime: 0x12344321,
        };

        subject.marshal(Direction::Response, &mut buffer).unwrap();

        assert_eq!(
            buffer,
            [
                0x43, 0x21, 0x12, 0x34, // epoch
                0x12, 0x34, 0x43, 0x21, // internal port, external port
                0x12, 0x34, 0x43, 0x21, // lifetime
            ]
        );
    }

    #[test]
    fn try_from_request_complains_about_short_buffer() {
        let buffer: &[u8] = &[0x00u8; 9];

        let result = MapOpcodeData::try_from((Direction::Request, buffer)).err();

        assert_eq!(result, Some(ParseError::ShortBuffer(10, 9)));
    }

    #[test]
    fn try_from_response_complains_about_short_buffer() {
        let buffer: &[u8] = &[0x00u8; 11];

        let result = MapOpcodeData::try_from((Direction::Response, buffer)).err();

        assert_eq!(result, Some(ParseError::ShortBuffer(12, 11)));
    }

    #[test]
    fn try_from_request_works() {
        let buffer: &[u8] = &[
            0x00, 0x00, // reserved
            0x12, 0x34, 0x43, 0x21, // internal port, external port
            0x12, 0x34, 0x43, 0x21, // lifetime
        ];

        let result = MapOpcodeData::try_from((Direction::Request, buffer)).unwrap();

        assert_eq!(
            result,
            MapOpcodeData {
                epoch_opt: None,
                internal_port: 0x1234,
                external_port: 0x4321,
                lifetime: 0x12344321,
            }
        );
    }

    #[test]
    fn try_from_response_works() {
        let buffer: &[u8] = &[
            0x43, 0x21, 0x12, 0x34, // epoch
            0x12, 0x34, 0x43, 0x21, // internal port, external port
            0x12, 0x34, 0x43, 0x21, // lifetime
        ];

        let result = MapOpcodeData::try_from((Direction::Response, buffer)).unwrap();

        assert_eq!(
            result,
            MapOpcodeData {
                epoch_opt: Some(0x43211234),
                internal_port: 0x1234,
                external_port: 0x4321,
                lifetime: 0x12344321,
            }
        );
    }

    #[test]
    fn knows_length() {
        let subject = MapOpcodeData::default();

        assert_eq!(subject.len(Direction::Request), 10);
        assert_eq!(subject.len(Direction::Response), 12);
    }
}
