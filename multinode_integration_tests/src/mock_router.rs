use crate::main::CONTROL_STREAM_PORT;
use crate::masq_node::DataProbeUtils;
use crate::utils::{do_docker_run, wait_for_startup};
use node_lib::test_utils::data_hunk_framer::DataHunkFramer;
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr, TcpStream};

pub trait MockRouter {
    fn announce_ip_change(&self, target_ip: IpAddr, new_ip_address: IpAddr);
}

pub struct MockPcpRouter {
    control_stream: TcpStream,
    framer: DataHunkFramer,
}

impl MockRouter for MockPcpRouter {
    fn announce_ip_change(&self, _target_ip: IpAddr, _new_ip_address: IpAddr) {
        todo!()
    }
}

impl MockPcpRouter {
    pub fn new(port: u16) -> Self {
        let control_stream = Self::start(port);
        Self {
            control_stream,
            framer: DataHunkFramer::new()
        }
    }

    fn start(port: u16) -> TcpStream {
        let name = "pcp_router".to_string();
        DataProbeUtils::clean_up_existing_container(&name[..]);
        let mock_router_args = Self::make_mock_router_args(port);
        do_docker_run(node_addr.ip_addr(), host_node_parent_dir, &name, mock_router_args);
        let wait_addr = SocketAddr::new(node_addr.ip_addr(), CONTROL_STREAM_PORT);
        let control_stream = wait_for_startup(wait_addr, &name);
        control_stream
    }
}
