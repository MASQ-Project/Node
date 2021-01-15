// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::utils::{OpcodeData, MarshalError, Direction};
use std::any::Any;
use crate::protocols::pmp::pmp_packet::PmpOpcodeData;

pub struct MapOpcodeData {
    // internal_port: u16,
    // external_port: u16,
    // lifetime: u32,
}

impl OpcodeData for MapOpcodeData {
    fn marshal(&self, _direction: Direction, _buf: &mut [u8]) -> Result<(), MarshalError> {
        unimplemented!()
    }

    fn len(&self, _direction: Direction) -> usize {
        unimplemented!()
    }

    fn as_any(&self) -> &dyn Any {
        unimplemented!()
    }
}

impl PmpOpcodeData for MapOpcodeData {}

impl MapOpcodeData {

}