// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::{Transactor, DeleteMappingError, AddMappingError, FindRoutersError, GetPublicIpError};
use std::net::IpAddr;

pub struct PmpTransactor {

}

impl Transactor for PmpTransactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, FindRoutersError> {
        unimplemented!()
    }

    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, GetPublicIpError> {
        unimplemented!()
    }

    fn add_mapping(&self, router_ip: IpAddr, hole_port: u16, lifetime: u32) -> Result<u32, AddMappingError> {
        unimplemented!()
    }

    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), DeleteMappingError> {
        unimplemented!()
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn nothing() {

    }
}
