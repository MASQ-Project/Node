// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::utils::{OpcodeData, MarshalError, Direction, u32_at, ParseError};
use std::any::Any;
use crate::protocols::pmp::pmp_packet::PmpOpcodeData;
use std::net::Ipv4Addr;

#[derive (Clone, Debug, PartialEq)]
pub struct GetOpcodeData {
    pub epoch_opt: Option<u32>,
    pub external_ip_address_opt: Option<Ipv4Addr>,
}

impl OpcodeData for GetOpcodeData {
    fn marshal(&self, direction: Direction, _buf: &mut [u8]) -> Result<(), MarshalError> {
        match direction {
            Direction::Request => Ok (()),
            Direction::Response => unimplemented!(),
        }
    }

    fn len(&self, direction: Direction) -> usize {
        match direction {
            Direction::Request => 0,
            Direction::Response => unimplemented!()
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PmpOpcodeData for GetOpcodeData {}

impl GetOpcodeData {
    pub fn new (direction: Direction, buf: &[u8]) -> Result<Self, ParseError> {
        match direction {
            Direction::Request => {
                Ok (Self {
                    epoch_opt: None,
                    external_ip_address_opt: None,
                })
            },
            Direction::Response => {
                if buf.len() < 8 {
                    unimplemented!()
                }
                Ok(Self {
                    epoch_opt: Some (u32_at (buf, 0)),
                    external_ip_address_opt: Some (Ipv4Addr::new (buf[4], buf[5], buf[6], buf[7]))
                })
            }
        }
    }
}