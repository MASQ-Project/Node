// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::command::Command;
use crate::main::CONTROL_STREAM_PORT;
use crate::substratum_client::SubstratumNodeClient;
use crate::substratum_node::NodeReference;
use crate::substratum_node::PortSelector;
use crate::substratum_node::SubstratumNode;
use crate::substratum_node::SubstratumNodeUtils;
use node_lib::hopper::live_cores_package::LiveCoresPackage;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::masquerader::Masquerader;
use node_lib::neighborhood::gossip::Gossip;
use node_lib::neighborhood::gossip::GossipBuilder;
use node_lib::neighborhood::neighborhood_database::NodeRecord;
use node_lib::sub_lib::cryptde::CryptDE;
use node_lib::sub_lib::cryptde::CryptData;
use node_lib::sub_lib::cryptde::PlainData;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::dispatcher::Component;
use node_lib::sub_lib::framer::Framer;
use node_lib::sub_lib::hopper::IncipientCoresPackage;
use node_lib::sub_lib::neighborhood::{RatePack, ZERO_RATE_PACK};
use node_lib::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::sub_lib::route::Route;
use node_lib::sub_lib::route::RouteSegment;
use node_lib::sub_lib::utils::indicates_dead_stream;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils::data_hunk::DataHunk;
use node_lib::test_utils::data_hunk_framer::DataHunkFramer;
use serde_cbor;
use std::cell::RefCell;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

pub struct SubstratumMockNode {
    control_stream: RefCell<TcpStream>,
    guts: Rc<SubstratumMockNodeGuts>,
}

impl Clone for SubstratumMockNode {
    fn clone(&self) -> Self {
        SubstratumMockNode {
            control_stream: RefCell::new(self.control_stream.borrow().try_clone().unwrap()),
            guts: Rc::clone(&self.guts),
        }
    }
}

impl SubstratumNode for SubstratumMockNode {
    fn name(&self) -> &str {
        self.guts.name.as_str()
    }

    fn node_reference(&self) -> NodeReference {
        NodeReference::new(
            self.cryptde().public_key(),
            self.node_addr().ip_addr(),
            self.node_addr().ports(),
        )
    }

    fn public_key(&self) -> PublicKey {
        self.cryptde().public_key()
    }

    fn cryptde(&self) -> CryptDENull {
        CryptDENull::from(&self.public_key())
    }

    fn ip_address(&self) -> IpAddr {
        self.guts.node_addr.ip_addr()
    }

    fn port_list(&self) -> Vec<u16> {
        self.guts.node_addr.ports().clone()
    }

    fn node_addr(&self) -> NodeAddr {
        self.guts.node_addr.clone()
    }

    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr {
        SubstratumNodeUtils::socket_addr(&self.node_addr(), port_selector, self.name())
    }

    fn earning_wallet(&self) -> Wallet {
        self.guts.earning_wallet.clone()
    }

    fn consuming_wallet(&self) -> Option<Wallet> {
        self.guts.consuming_wallet.clone()
    }

    fn rate_pack(&self) -> RatePack {
        ZERO_RATE_PACK.clone()
    }

    fn make_client(&self, _port: u16) -> SubstratumNodeClient {
        unimplemented!()
    }
}

impl SubstratumMockNode {
    pub fn start(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
    ) -> SubstratumMockNode {
        let name = format!("mock_node_{}", index);
        let node_addr = NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(172, 18, 1, index as u8)), &ports);
        let earning_wallet = Wallet::new(format!("{}_earning", name).as_str());
        let consuming_wallet = Some(Wallet::new(format!("{}_consuming", name).as_str()));
        SubstratumNodeUtils::clean_up_existing_container(&name[..]);
        Self::do_docker_run(&node_addr, host_node_parent_dir, &name);
        let wait_addr = SocketAddr::new(node_addr.ip_addr(), CONTROL_STREAM_PORT);
        let control_stream = RefCell::new(Self::wait_for_startup(wait_addr, &name));
        let mut cryptde = Box::new(CryptDENull::new());
        cryptde.generate_key_pair();
        let framer = RefCell::new(DataHunkFramer::new());
        let guts = Rc::new(SubstratumMockNodeGuts {
            name,
            node_addr,
            earning_wallet,
            consuming_wallet,
            cryptde,
            framer,
        });
        SubstratumMockNode {
            control_stream,
            guts,
        }
    }

    pub fn bootstrap_from(&self, node: &dyn SubstratumNode) {
        let masquerader = JsonMasquerader::new();
        let mut node_record = NodeRecord::new(
            &self.public_key(),
            Some(&self.node_addr()),
            node.earning_wallet(),
            node.consuming_wallet(),
            DEFAULT_RATE_PACK.clone(),
            false,
            None,
            0,
        );
        node_record.sign(self.cryptde());

        let gossip = GossipBuilder::new().node(&node_record, true).build();
        let route = Route::one_way(
            RouteSegment::new(
                vec![&self.public_key(), &node.public_key()],
                Component::Neighborhood,
            ),
            self.cryptde(),
            node.consuming_wallet().clone(),
        )
        .unwrap();
        let package =
            IncipientCoresPackage::new(self.cryptde(), route, gossip, &node.public_key()).unwrap();

        self.transmit_package(
            *node.port_list().first().unwrap(),
            package,
            &masquerader,
            &node.public_key(),
            node.socket_addr(PortSelector::First),
        )
        .unwrap();
    }

    pub fn transmit_data(&self, data_hunk: DataHunk) -> Result<(), io::Error> {
        let to_transmit: Vec<u8> = data_hunk.into();
        match self.control_stream.borrow_mut().write(&to_transmit[..]) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn transmit_package(
        &self,
        transmit_port: u16,
        package: IncipientCoresPackage,
        masquerader: &dyn Masquerader,
        target_key: &PublicKey,
        target_addr: SocketAddr,
    ) -> Result<(), io::Error> {
        let (lcp, _) = LiveCoresPackage::from_incipient(package, self.cryptde()).unwrap();
        let lcp_data = serde_cbor::ser::to_vec(&lcp).unwrap();
        let encrypted_data = self
            .cryptde()
            .encode(target_key, &PlainData::new(&lcp_data[..]))
            .unwrap();
        let masked_data = masquerader.mask(encrypted_data.as_slice()).unwrap();
        let data_hunk = DataHunk::new(
            SocketAddr::new(self.ip_address(), transmit_port),
            target_addr,
            masked_data,
        );
        self.transmit_data(data_hunk)
    }

    pub fn wait_for_data(&self, timeout: Duration) -> Result<DataHunk, io::Error> {
        let mut buf = [0u8; 16384];
        let mut framer = self.guts.framer.borrow_mut();
        let mut control_stream = self.control_stream.borrow_mut();
        control_stream.set_read_timeout(Some(timeout)).unwrap();
        loop {
            match framer.take_frame() {
                Some(framed_chunk) => {
                    let data_hunk = DataHunk::from(framed_chunk.chunk);
                    return Ok(data_hunk);
                }
                None => match control_stream.read(&mut buf) {
                    Err(ref e) if indicates_dead_stream(e.kind()) => {
                        panic!("Couldn't read control stream from {}: {}", self.name(), e)
                    }
                    Err(e) => {
                        println!("No data from {} after {:?}", self.name(), timeout);
                        return Err(e);
                    }
                    Ok(0) => panic!("{} dropped its control stream", self.name()),
                    Ok(len) => framer.add_data(&buf[..len]),
                },
            }
        }
    }

    pub fn wait_for_package(
        &self,
        masquerader: &dyn Masquerader,
        timeout: Duration,
    ) -> Result<(SocketAddr, SocketAddr, LiveCoresPackage), io::Error> {
        let data_hunk = self.wait_for_data(timeout)?;
        let unmasked_data = masquerader.try_unmask(&data_hunk.data[..]).unwrap().chunk;
        let decrypted_data = self
            .cryptde()
            .decode(&CryptData::new(&unmasked_data[..]))
            .unwrap();
        let live_cores_package =
            serde_cbor::de::from_slice::<LiveCoresPackage>(decrypted_data.as_slice()).unwrap();
        Ok((data_hunk.from, data_hunk.to, live_cores_package))
    }

    pub fn wait_for_gossip(&self, timeout: Duration) -> Option<Gossip> {
        let masquerader = JsonMasquerader::new();
        match self.wait_for_package(&masquerader, timeout) {
            Ok((from, _, package)) => {
                let incoming_cores_package = package.to_expired(from.ip(), self.cryptde()).unwrap();
                incoming_cores_package
                    .payload::<Gossip>(self.cryptde())
                    .ok()
            }
            Err(_) => None,
        }
    }

    pub fn cryptde(&self) -> &dyn CryptDE {
        self.guts.cryptde.as_ref()
    }

    fn do_docker_run(node_addr: &NodeAddr, host_node_parent_dir: Option<String>, name: &String) {
        let root = match host_node_parent_dir {
            Some(dir) => dir,
            None => SubstratumNodeUtils::find_project_root(),
        };
        let command_dir = format!("{}/node/target/release", root);
        let mock_node_args = Self::make_node_args(&node_addr);
        let docker_command = "docker";
        let ip_addr_string = format!("{}", node_addr.ip_addr());
        let name_string = name.clone();
        let v_param = format!("{}:/node_root/node", command_dir);
        let mut docker_args = Command::strings(vec![
            "run",
            "--detach",
            "--ip",
            ip_addr_string.as_str(),
            "--name",
            name_string.as_str(),
            "--net",
            "integration_net",
            "-v",
            v_param.as_str(),
            "test_node_image",
            "/node_root/node/MockNode",
        ]);
        docker_args.extend(mock_node_args);
        let mut command = Command::new(docker_command, docker_args);
        command.stdout_or_stderr().unwrap();
    }

    fn wait_for_startup(wait_addr: SocketAddr, name: &String) -> TcpStream {
        let mut retries = 10;
        let mut stream: Option<TcpStream> = None;
        loop {
            match TcpStream::connect(wait_addr) {
                Ok(s) => {
                    println!("{} startup detected on {}", name, wait_addr);
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    println!("{} not yet started on {}: {}", name, wait_addr, e);
                    ()
                }
            }
            retries -= 1;
            if retries <= 0 {
                break;
            }
            thread::sleep(Duration::from_millis(100))
        }
        if retries <= 0 {
            panic!("Timed out trying to contact {}", name)
        }
        stream.unwrap()
    }

    fn make_node_args(node_addr: &NodeAddr) -> Vec<String> {
        vec![format!("{}", node_addr)]
    }
}

struct SubstratumMockNodeGuts {
    name: String,
    node_addr: NodeAddr,
    earning_wallet: Wallet,
    consuming_wallet: Option<Wallet>,
    cryptde: Box<dyn CryptDE>,
    framer: RefCell<DataHunkFramer>,
}

impl Drop for SubstratumMockNodeGuts {
    fn drop(&mut self) {
        SubstratumNodeUtils::stop(self.name.as_str());
    }
}
