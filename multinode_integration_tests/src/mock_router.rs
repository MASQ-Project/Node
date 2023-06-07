use std::net::IpAddr;
use crate::masq_real_node::MASQRealNode;

pub trait MockRouter {
    fn announce_ip_change(&self, target_ip: IpAddr, new_ip_address: IpAddr);
}

pub struct MockPcpRouter {}

impl MockRouter for MockPcpRouter {
    fn announce_ip_change(&self, target_ip: IpAddr, new_ip_address: IpAddr) {
        todo!()
    }
}

impl MockPcpRouter {
    pub fn new () -> Self {
        Self {}
    }
}
