use crate::main::CONTROL_STREAM_PORT;
use crate::masq_node::DataProbeUtils;
use crate::utils::{do_docker_run, wait_for_startup};
use node_lib::test_utils::data_hunk_framer::DataHunkFramer;
use std::net::{IpAddr, SocketAddr, TcpStream};

pub trait MockRouter {
    fn announce_ip_change(&self, target_ip: IpAddr, new_ip_address: IpAddr);
}

#[allow(dead_code)]
pub struct MockPcpRouter {
    name: String,
    ip_addr: IpAddr,
    control_stream: TcpStream,
    framer: DataHunkFramer,
}

impl MockRouter for MockPcpRouter {
    fn announce_ip_change(&self, _target_ip: IpAddr, _new_ip_address: IpAddr) {
        todo!()
    }
}

impl MockPcpRouter {
    pub fn new(name: &str, ip_addr: IpAddr) -> Self {
        let control_stream = Self::start(ip_addr);
        Self {
            name: name.to_string(),
            ip_addr,
            control_stream,
            framer: DataHunkFramer::new(),
        }
    }

    fn start(ip_addr: IpAddr) -> TcpStream {
        let name = "pcp_router".to_string();
        DataProbeUtils::clean_up_existing_container(&name[..]);
        let mock_router_args = vec![format!("{}:U5351", ip_addr)];
        do_docker_run(ip_addr, None, &name, mock_router_args);
        let wait_addr = SocketAddr::new(ip_addr, CONTROL_STREAM_PORT);
        wait_for_startup(wait_addr, &name)
    }
}
