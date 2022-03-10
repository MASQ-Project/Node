// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::command::Command;
use crate::main::CONTROL_STREAM_PORT;
use crate::masq_node::MASQNode;
use crate::masq_node::MASQNodeUtils;
use crate::masq_node::NodeReference;
use crate::masq_node::PortSelector;
use crate::multinode_gossip::{Introduction, MultinodeGossip, SingleNode};
use masq_lib::blockchains::chains::Chain;
use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;
use node_lib::hopper::live_cores_package::LiveCoresPackage;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::masquerader::{MasqueradeError, Masquerader};
use node_lib::neighborhood::gossip::Gossip_0v1;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde::{encodex, CryptDE};
use node_lib::sub_lib::cryptde::{CodexError, CryptData, CryptdecError};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::cryptde_real::CryptDEReal;
use node_lib::sub_lib::framer::Framer;
use node_lib::sub_lib::hopper::{IncipientCoresPackage, MessageType};
use node_lib::sub_lib::neighborhood::{GossipFailure_0v1, RatePack, DEFAULT_RATE_PACK};
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::sub_lib::route::Route;
use node_lib::sub_lib::utils::indicates_dead_stream;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils::data_hunk::DataHunk;
use node_lib::test_utils::data_hunk_framer::DataHunkFramer;
use node_lib::test_utils::{make_paying_wallet, make_wallet};
use std::cell::RefCell;
use std::convert::TryFrom;
use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::{IpAddr, Shutdown};
use std::ops::Add;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

pub struct MASQMockNode {
    control_stream: RefCell<TcpStream>,
    guts: Rc<MASQMockNodeGuts>,
}

enum CryptDEEnum {
    Real(CryptDEReal),
    Fake((CryptDENull, CryptDENull)),
}

impl Clone for MASQMockNode {
    fn clone(&self) -> Self {
        MASQMockNode {
            control_stream: RefCell::new(self.control_stream.borrow().try_clone().unwrap()),
            guts: Rc::clone(&self.guts),
        }
    }
}

impl MASQNode for MASQMockNode {
    fn name(&self) -> &str {
        self.guts.name.as_str()
    }

    fn node_reference(&self) -> NodeReference {
        NodeReference::new(
            self.signing_cryptde().unwrap().public_key().clone(),
            Some(self.node_addr().ip_addr()),
            self.node_addr().ports(),
            self.chain(),
        )
    }

    fn main_cryptde_null(&self) -> Option<&CryptDENull> {
        match &self.guts.cryptde_enum {
            CryptDEEnum::Fake((ref cryptde_null, _)) => Some(cryptde_null),
            CryptDEEnum::Real(_) => None,
        }
    }

    fn alias_cryptde_null(&self) -> Option<&CryptDENull> {
        match &self.guts.cryptde_enum {
            CryptDEEnum::Fake((_, ref cryptde_null)) => Some(cryptde_null),
            CryptDEEnum::Real(_) => None,
        }
    }

    fn signing_cryptde(&self) -> Option<&dyn CryptDE> {
        match &self.guts.cryptde_enum {
            CryptDEEnum::Fake((ref cryptde_null, _)) => Some(cryptde_null),
            CryptDEEnum::Real(ref cryptde_real) => Some(cryptde_real),
        }
    }

    fn main_public_key(&self) -> &PublicKey {
        self.signing_cryptde().unwrap().public_key()
    }

    fn ip_address(&self) -> IpAddr {
        self.guts.node_addr.ip_addr()
    }

    fn port_list(&self) -> Vec<u16> {
        self.guts.node_addr.ports()
    }

    fn node_addr(&self) -> NodeAddr {
        self.guts.node_addr.clone()
    }

    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr {
        MASQNodeUtils::socket_addr(&self.node_addr(), port_selector, self.name())
    }

    fn earning_wallet(&self) -> Wallet {
        self.guts.earning_wallet.clone()
    }

    fn consuming_wallet(&self) -> Option<Wallet> {
        self.guts.consuming_wallet.clone()
    }

    fn rate_pack(&self) -> RatePack {
        self.guts.rate_pack.clone()
    }

    fn chain(&self) -> Chain {
        self.guts.chain
    }

    fn accepts_connections(&self) -> bool {
        true // just a guess
    }

    fn routes_data(&self) -> bool {
        true // just a guess
    }
}

impl MASQMockNode {
    pub fn start_with_public_key(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        public_key: &PublicKey,
        chain: Chain,
    ) -> MASQMockNode {
        let main_cryptde = CryptDENull::from(public_key, chain);
        let mut key = public_key.as_slice().to_vec();
        key.reverse();
        let alias_cryptde = CryptDENull::from(&PublicKey::new(&key), chain);
        let cryptde_enum = CryptDEEnum::Fake((main_cryptde, alias_cryptde));
        Self::start_with_cryptde_enum(ports, index, host_node_parent_dir, cryptde_enum)
    }

    pub fn start(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        chain: Chain,
    ) -> MASQMockNode {
        let cryptde_enum = CryptDEEnum::Real(CryptDEReal::new(chain));
        Self::start_with_cryptde_enum(ports, index, host_node_parent_dir, cryptde_enum)
    }

    fn start_with_cryptde_enum(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        cryptde_enum: CryptDEEnum,
    ) -> MASQMockNode {
        let name = format!("mock_node_{}", index);
        let node_addr = NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(172, 18, 1, index as u8)), &ports);
        let earning_wallet = make_wallet(format!("{}_earning", name).as_str());
        let consuming_wallet = Some(make_paying_wallet(format!("{}_consuming", name).as_bytes()));
        MASQNodeUtils::clean_up_existing_container(&name[..]);
        Self::do_docker_run(&node_addr, host_node_parent_dir, &name);
        let wait_addr = SocketAddr::new(node_addr.ip_addr(), CONTROL_STREAM_PORT);
        let control_stream = RefCell::new(Self::wait_for_startup(wait_addr, &name));
        let framer = RefCell::new(DataHunkFramer::new());
        let guts = Rc::new(MASQMockNodeGuts {
            name,
            node_addr,
            earning_wallet,
            consuming_wallet,
            rate_pack: DEFAULT_RATE_PACK.clone(),
            cryptde_enum,
            framer,
            chain: TEST_DEFAULT_MULTINODE_CHAIN,
        });
        MASQMockNode {
            control_stream,
            guts,
        }
    }

    pub fn cryptde_real(&self) -> Option<&CryptDEReal> {
        match &self.guts.cryptde_enum {
            CryptDEEnum::Fake(_) => None,
            CryptDEEnum::Real(ref cryptde_real) => Some(cryptde_real),
        }
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
        let (lcp, _) =
            LiveCoresPackage::from_incipient(package, self.signing_cryptde().unwrap()).unwrap();
        let encrypted_data = encodex(self.signing_cryptde().unwrap(), target_key, &lcp).unwrap();
        let masked_data = masquerader.mask(encrypted_data.as_slice()).unwrap();
        let data_hunk = DataHunk::new(
            SocketAddr::new(self.ip_address(), transmit_port),
            target_addr,
            masked_data,
        );
        self.transmit_data(data_hunk)
    }

    pub fn transmit_gossip(
        &self,
        transmit_port: u16,
        gossip: Gossip_0v1,
        target_key: &PublicKey,
        target_addr: SocketAddr,
    ) -> Result<(), io::Error> {
        let masquerader = JsonMasquerader::new();
        let route = Route::single_hop(target_key, self.signing_cryptde().unwrap()).unwrap();
        let package = IncipientCoresPackage::new(
            self.signing_cryptde().unwrap(),
            route,
            MessageType::Gossip(gossip.into()),
            target_key,
        )
        .unwrap();
        self.transmit_package(
            transmit_port,
            package,
            &masquerader,
            target_key,
            target_addr,
        )
    }

    pub fn transmit_debut(&self, receiver: &dyn MASQNode) -> Result<(), io::Error> {
        self.transmit_multinode_gossip(receiver, &SingleNode::new(self))
    }

    pub fn transmit_pass(
        &self,
        receiver: &dyn MASQNode,
        target: &dyn MASQNode,
    ) -> Result<(), io::Error> {
        self.transmit_multinode_gossip(receiver, &SingleNode::new(target))
    }

    pub fn transmit_introduction(
        &self,
        receiver: &dyn MASQNode,
        introducee: &dyn MASQNode,
    ) -> Result<(), io::Error> {
        self.transmit_multinode_gossip(receiver, &Introduction::new(self, introducee))
    }

    pub fn transmit_multinode_gossip(
        &self,
        receiver: &dyn MASQNode,
        multinode_gossip: &dyn MultinodeGossip,
    ) -> Result<(), io::Error> {
        let gossip = multinode_gossip.render();
        self.transmit_gossip(
            receiver.port_list()[0],
            gossip,
            receiver.main_public_key(),
            receiver.socket_addr(PortSelector::First),
        )
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
        let stop_at = Instant::now().add(timeout);
        let mut accumulated_data: Vec<u8> = vec![];
        // dunno why these are a problem; they _are_ used on the last line of the function.
        #[allow(unused_assignments)]
        let mut from_opt: Option<SocketAddr> = None;
        #[allow(unused_assignments)]
        let mut to_opt: Option<SocketAddr> = None;
        let unmasked_chunk: Vec<u8> = loop {
            match self.wait_for_data(Duration::from_millis(100)) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() > stop_at {
                        return Err(Error::from(ErrorKind::WouldBlock));
                    }
                    continue;
                }
                Err(e) => return Err(e),
                Ok(data_hunk) => {
                    accumulated_data.extend(data_hunk.data);
                    from_opt = Some(data_hunk.from);
                    to_opt = Some(data_hunk.to);
                    match masquerader.try_unmask(&accumulated_data) {
                        Err(MasqueradeError::NotThisMasquerader) => {
                            panic!("Wrong Masquerader supplied to wait_for_package")
                        }
                        Err(_) => continue,
                        Ok(unmasked_chunk) => break unmasked_chunk.chunk,
                    }
                }
            }
        };
        let decrypted_data = self
            .signing_cryptde()
            .unwrap()
            .decode(&CryptData::new(&unmasked_chunk[..]))
            .unwrap();
        let live_cores_package =
            serde_cbor::de::from_slice::<LiveCoresPackage>(decrypted_data.as_slice()).unwrap();
        Ok((from_opt.unwrap(), to_opt.unwrap(), live_cores_package))
    }

    pub fn wait_for_gossip(&self, timeout: Duration) -> Option<(Gossip_0v1, IpAddr)> {
        let masquerader = JsonMasquerader::new();
        match self.wait_for_package(&masquerader, timeout) {
            Ok((from, _, package)) => {
                let incoming_cores_package = match package.to_expired(
                    from,
                    self.main_cryptde_null().unwrap(),
                    self.alias_cryptde_null().unwrap(),
                ) {
                    Ok(icp) => icp,
                    Err(CodexError::DecryptionError(CryptdecError::OpeningFailed)) => match package
                        .to_expired(
                            from,
                            self.main_cryptde_null().unwrap(),
                            self.main_cryptde_null().unwrap(),
                        ) {
                        Ok(icp) => icp,
                        Err(e) => panic!("Couldn't expire LiveCoresPackage: {:?}", e),
                    },
                    Err(e) => panic!("Couldn't expire LiveCoresPackage: {:?}", e),
                };
                match incoming_cores_package.payload {
                    MessageType::Gossip(vd) => Some((
                        Gossip_0v1::try_from(vd).expect("Couldn't deserialize Gossip"),
                        from.ip(),
                    )),
                    _ => panic!("Expected Gossip, got something else"),
                }
            }
            Err(_) => None,
        }
    }

    pub fn wait_for_gossip_failure(
        &self,
        timeout: Duration,
    ) -> Option<(GossipFailure_0v1, IpAddr)> {
        let masquerader = JsonMasquerader::new();
        match self.wait_for_package(&masquerader, timeout) {
            Ok((from, _, package)) => {
                let incoming_cores_package = package
                    .to_expired(
                        from,
                        self.signing_cryptde().unwrap(),
                        self.signing_cryptde().unwrap(),
                    )
                    .unwrap();
                match incoming_cores_package.payload {
                    MessageType::GossipFailure(g) => Some((
                        g.extract(&node_lib::sub_lib::migrations::gossip_failure::MIGRATIONS)
                            .unwrap(),
                        from.ip(),
                    )),
                    _ => panic!("Expected GossipFailure, got something else"),
                }
            }
            Err(_) => None,
        }
    }

    pub fn kill(self) {
        let mut stream = self.control_stream.borrow_mut();
        stream.flush().unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
    }

    fn do_docker_run(node_addr: &NodeAddr, host_node_parent_dir: Option<String>, name: &str) {
        let root = match host_node_parent_dir {
            Some(dir) => dir,
            None => MASQNodeUtils::find_project_root(),
        };
        let command_dir = format!("{}/node/target/release", root);
        let mock_node_args = Self::make_node_args(node_addr);
        let docker_command = "docker";
        let ip_addr_string = format!("{}", node_addr.ip_addr());
        let v_param = format!("{}:/node_root/node", command_dir);
        let mut docker_args = Command::strings(vec![
            "run",
            "--detach",
            "--ip",
            &ip_addr_string,
            "--name",
            name,
            "--net",
            "integration_net",
            "-v",
            v_param.as_str(),
            "test_node_image",
            "/node_root/node/mock_node",
        ]);
        docker_args.extend(mock_node_args);
        let mut command = Command::new(docker_command, docker_args);
        command.stdout_or_stderr().unwrap();
    }

    fn wait_for_startup(wait_addr: SocketAddr, name: &str) -> TcpStream {
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

struct MASQMockNodeGuts {
    name: String,
    node_addr: NodeAddr,
    earning_wallet: Wallet,
    consuming_wallet: Option<Wallet>,
    rate_pack: RatePack,
    cryptde_enum: CryptDEEnum,
    framer: RefCell<DataHunkFramer>,
    chain: Chain,
}

impl Drop for MASQMockNodeGuts {
    fn drop(&mut self) {
        MASQNodeUtils::stop(self.name.as_str());
    }
}
