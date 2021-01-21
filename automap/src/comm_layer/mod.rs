// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::IpAddr;

pub mod pcp;
pub mod pmp;
pub mod igdp;

pub enum FindRoutersError {

}

pub enum GetPublicIpError {

}

pub enum AddMappingError {

}

pub enum DeleteMappingError {

}

pub trait Transactor {
    fn find_routers () -> Result<Vec<IpAddr>, FindRoutersError>;
    fn get_public_ip (router_ip: IpAddr) -> Result<IpAddr, GetPublicIpError>;
    fn add_mapping (router_ip: IpAddr, hole_port: u16, )
}

pub struct GetPublicIp {

}

pub struct AddMapping {

}

pub struct DeleteMapping {

}
