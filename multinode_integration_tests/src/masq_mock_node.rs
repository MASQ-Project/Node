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
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::sub_lib::cryptde::CryptData;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde::{encodex, CryptDE};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::cryptde_real::CryptDEReal;
use node_lib::sub_lib::framer::Framer;
use node_lib::sub_lib::hopper::{
    ExpiredCoresPackage, IncipientCoresPackage, MessageType, MessageTypeLite,
};
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
    // retain this Rc pointer because as long as there is at least one reference we won't drop
    // the actual structure, instead, only the reference count will be affected; unlike to situation
    // with this structure creating its clones directly, then the whole Docker container would
    // immediately halt for this Node...because that's how its Drop implementation works...
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

    fn alias_public_key(&self) -> &PublicKey {
        self.alias_cryptde_null().unwrap().public_key()
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
        self.guts.rate_pack
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

pub struct MutableMASQMockNode {
    pub control_stream: RefCell<TcpStream>,
    configurable_guts: MASQMockNodeGuts,
}

impl MutableMASQMockNode {
    pub fn absorb_configuration(&mut self, node_record: &NodeRecord) {
        // Copy attributes from the NodeRecord into the MASQNode.
        self.configurable_guts.earning_wallet = node_record.earning_wallet();
        self.configurable_guts.rate_pack = *node_record.rate_pack();
    }
}

impl From<MutableMASQMockNode> for MASQMockNode {
    fn from(mutable_handle: MutableMASQMockNode) -> Self {
        MASQMockNode {
            control_stream: mutable_handle.control_stream,
            guts: Rc::new(mutable_handle.configurable_guts),
        }
    }
}

pub trait MASQMockNodeStarter<T> {
    fn start(
        &self,
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        public_key_opt: Option<&PublicKey>,
        chain: Chain,
    ) -> T;
}

pub struct ImmutableMASQMockNodeStarter {}

impl MASQMockNodeStarter<MASQMockNode> for ImmutableMASQMockNodeStarter {
    fn start(
        &self,
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        public_key_opt: Option<&PublicKey>,
        chain: Chain,
    ) -> MASQMockNode {
        let (control_stream, mock_node_guts) = MASQMockNode::start_masq_mock_node_with_bare_guts(
            ports,
            index,
            host_node_parent_dir,
            public_key_opt,
            chain,
        );
        MASQMockNode {
            control_stream,
            guts: Rc::new(mock_node_guts),
        }
    }
}

pub struct MutableMASQMockNodeStarter {}

impl MASQMockNodeStarter<MutableMASQMockNode> for MutableMASQMockNodeStarter {
    fn start(
        &self,
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        public_key_opt: Option<&PublicKey>,
        chain: Chain,
    ) -> MutableMASQMockNode {
        let (control_stream, mock_node_guts) = MASQMockNode::start_masq_mock_node_with_bare_guts(
            ports,
            index,
            host_node_parent_dir,
            public_key_opt,
            chain,
        );
        MutableMASQMockNode {
            control_stream,
            configurable_guts: mock_node_guts,
        }
    }
}

impl MASQMockNode {
    pub fn cryptde_real(&self) -> Option<&CryptDEReal> {
        match &self.guts.cryptde_enum {
            CryptDEEnum::Fake(_) => None,
            CryptDEEnum::Real(ref cryptde_real) => Some(cryptde_real),
        }
    }

    pub fn transmit_data(&self, data_hunk: DataHunk) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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

    pub fn transmit_debut(&self, receiver: &dyn MASQNode) -> Result<(), Error> {
        let gossip = SingleNode::new(self);
        self.transmit_multinode_gossip(receiver, &gossip)
    }

    pub fn transmit_pass(
        &self,
        receiver: &dyn MASQNode,
        target: &dyn MASQNode,
    ) -> Result<(), Error> {
        let gossip = SingleNode::new(target);
        self.transmit_multinode_gossip(receiver, &gossip)
    }

    pub fn transmit_introduction(
        &self,
        receiver: &dyn MASQNode,
        introducee: &dyn MASQNode,
    ) -> Result<(), Error> {
        let gossip = Introduction::new(self, introducee);
        self.transmit_multinode_gossip(receiver, &gossip)
    }

    pub fn transmit_multinode_gossip(
        &self,
        receiver: &dyn MASQNode,
        multinode_gossip: &dyn MultinodeGossip,
    ) -> Result<(), Error> {
        let gossip = multinode_gossip.render();
        self.transmit_gossip(
            receiver.port_list()[0],
            gossip,
            receiver.main_public_key(),
            receiver.socket_addr(PortSelector::First),
        )
    }

    pub fn wait_for_data(&self, timeout: Duration) -> Result<DataHunk, Error> {
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
    ) -> Result<(SocketAddr, SocketAddr, LiveCoresPackage), Error> {
        let stop_at = Instant::now().add(timeout);
        let mut accumulated_data: Vec<u8> = vec![];
        let (unmasked_chunk, socket_from, socket_to) = loop {
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
                    match masquerader.try_unmask(&accumulated_data) {
                        Err(MasqueradeError::NotThisMasquerader) => {
                            panic!("Wrong Masquerader supplied to wait_for_package")
                        }
                        Err(_) => continue,
                        Ok(unmasked_chunk) => {
                            break (unmasked_chunk.chunk, data_hunk.from, data_hunk.to)
                        }
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
        Ok((socket_from, socket_to, live_cores_package))
    }

    pub fn wait_for_specific_package(
        &self,
        message_type_lite: MessageTypeLite,
        immediate_neighbor: SocketAddr,
        exit_node_cryptde: Option<CryptDENull>,
    ) -> Option<ExpiredCoresPackage<MessageType>> {
        let public_key = self.main_public_key();
        let cryptde = CryptDENull::from(public_key, TEST_DEFAULT_MULTINODE_CHAIN);
        let exit_cryptde = exit_node_cryptde.unwrap_or_else(|| cryptde.clone());
        loop {
            if let Ok((_, _, live_cores_package)) =
                self.wait_for_package(&JsonMasquerader::new(), Duration::from_secs(2))
            {
                let (_, intended_exit_public_key) =
                    CryptDENull::extract_key_pair(public_key.len(), &live_cores_package.payload);
                assert_eq!(&intended_exit_public_key, exit_cryptde.public_key());
                let expired_cores_package = live_cores_package
                    .to_expired(immediate_neighbor, &cryptde, &exit_cryptde)
                    .unwrap();
                if message_type_lite == expired_cores_package.payload.clone().into() {
                    return Some(expired_cores_package);
                }
            } else {
                return None;
            }
        }
    }

    pub fn wait_for_gossip(&self, timeout: Duration) -> Option<(Gossip_0v1, IpAddr)> {
        let masquerader = JsonMasquerader::new();
        match self.wait_for_package(&masquerader, timeout) {
            Ok((from, _, package)) => {
                let incoming_cores_package = match package.to_expired(
                    from,
                    self.main_cryptde_null().unwrap(),
                    self.main_cryptde_null().unwrap(),
                ) {
                    Ok(icp) => icp,
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

    fn start_masq_mock_node_with_bare_guts(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        public_key_opt: Option<&PublicKey>,
        chain: Chain,
    ) -> (RefCell<TcpStream>, MASQMockNodeGuts) {
        let cryptde_enum = Self::initiate_cryptde_enum(public_key_opt, chain);
        Self::start_with_cryptde_enum(ports, index, host_node_parent_dir, cryptde_enum)
    }

    fn initiate_cryptde_enum(public_key_opt: Option<&PublicKey>, chain: Chain) -> CryptDEEnum {
        match public_key_opt {
            Some(public_key) => {
                let main_cryptde = CryptDENull::from(public_key, chain);
                let mut key = public_key.as_slice().to_vec();
                key.reverse();
                let alias_cryptde = CryptDENull::from(&PublicKey::new(&key), chain);
                CryptDEEnum::Fake((main_cryptde, alias_cryptde))
            }
            None => CryptDEEnum::Real(CryptDEReal::new(chain)),
        }
    }

    fn start_with_cryptde_enum(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
        cryptde_enum: CryptDEEnum,
    ) -> (RefCell<TcpStream>, MASQMockNodeGuts) {
        let name = format!("mock_node_{}", index);
        let node_addr = NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(172, 18, 1, index as u8)), &ports);
        let earning_wallet = make_wallet(format!("{}_earning", name).as_str());
        let consuming_wallet = Some(make_paying_wallet(format!("{}_consuming", name).as_bytes()));
        MASQNodeUtils::clean_up_existing_container(&name[..]);
        MASQMockNode::do_docker_run(&node_addr, host_node_parent_dir, &name);
        let wait_addr = SocketAddr::new(node_addr.ip_addr(), CONTROL_STREAM_PORT);
        let control_stream = RefCell::new(MASQMockNode::wait_for_startup(wait_addr, &name));
        let framer = RefCell::new(DataHunkFramer::new());
        let guts = MASQMockNodeGuts {
            name,
            node_addr,
            earning_wallet,
            consuming_wallet,
            rate_pack: DEFAULT_RATE_PACK,
            cryptde_enum,
            framer,
            chain: TEST_DEFAULT_MULTINODE_CHAIN,
        };
        (control_stream, guts)
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
