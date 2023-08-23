use crate::main::CONTROL_STREAM_PORT;
use crate::masq_node::DataProbeUtils;
use crate::utils::{do_docker_run, wait_for_startup};
use node_lib::test_utils::data_hunk_framer::DataHunkFramer;
use std::net::{IpAddr, SocketAddr, TcpStream};

pub trait MockRouter {
    fn announce_ip_change(&self, target_ip: IpAddr, new_ip_address: IpAddr);
}

pub struct MockPcpRouter {
    _control_stream: TcpStream,
    _framer: DataHunkFramer,
}

impl MockRouter for MockPcpRouter {
    fn announce_ip_change(&self, _target_ip: IpAddr, _new_ip_address: IpAddr) {
        todo!()
    }
}

impl MockPcpRouter {
    pub fn new(socket_addr: SocketAddr) -> Self {
        let control_stream = Self::start(socket_addr);
        Self {
            _control_stream: control_stream,
            _framer: DataHunkFramer::new(),
        }
    }

    pub fn start(socket_addr: SocketAddr) -> TcpStream {
        let name = "pcp_router".to_string();
        DataProbeUtils::clean_up_existing_container(&name[..]);
        let mock_router_args = Self::make_mock_router_args(socket_addr);
        do_docker_run(
            socket_addr.ip(),
            None,
            &name,
            mock_router_args,
        );
        let wait_addr = SocketAddr::new(socket_addr.ip(), CONTROL_STREAM_PORT);
        wait_for_startup(wait_addr, &name)
    }

    fn make_mock_router_args(_socket_addr: SocketAddr) -> Vec<String> {
        todo!();
    }
}
