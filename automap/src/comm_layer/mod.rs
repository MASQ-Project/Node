// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::IpAddr;

pub mod igdp;
pub mod pcp;
mod pcp_pmp_common;
pub mod pmp;

#[derive (Clone, PartialEq, Debug)]
pub enum AutomapError {

}

pub trait Transactor {
    fn find_routers (&self) -> Result<Vec<IpAddr>, AutomapError>;
    fn get_public_ip (&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError>;
    fn add_mapping (&self, router_ip: IpAddr, hole_port: u16, lifetime: u32) -> Result<u32, AutomapError>;
    fn delete_mapping (&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError>;
}
