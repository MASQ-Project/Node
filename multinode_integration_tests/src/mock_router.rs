use std::net::IpAddr;

pub trait MockRouter {
    fn announce_ip_change(&self, target_ip: IpAddr, new_ip_address: IpAddr);
}

pub struct MockPcpRouter {}

impl MockRouter for MockPcpRouter {
    fn announce_ip_change(&self, _target_ip: IpAddr, _new_ip_address: IpAddr) {
        todo!()
    }
}

impl Default for MockPcpRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPcpRouter {
    pub fn new () -> Self {
        Self {}
    }
}
