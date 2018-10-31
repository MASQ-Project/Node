// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::cell::RefCell;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::rc::Rc;
use serde_cbor;
use hopper_lib::hopper::LiveCoresPackage;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::node_addr::NodeAddr;
use sub_lib::utils::indicates_dead_stream;
use command::Command;
use substratum_client::SubstratumNodeClient;
use substratum_node::NodeReference;
use substratum_node::PortSelector;
use substratum_node::SubstratumNode;
use substratum_node::SubstratumNodeUtils;
use std::time::Duration;
use std::thread;
use node_lib::masquerader::Masquerader;
use sub_lib::cryptde::PlainData;
use sub_lib::cryptde::CryptData;
use test_utils::data_hunk::DataHunk;
use test_utils::data_hunk_framer::DataHunkFramer;
use sub_lib::framer::Framer;
use main::CONTROL_STREAM_PORT;

pub struct SubstratumMockNode {
    control_stream: RefCell<TcpStream>,
    guts: Rc<SubstratumMockNodeGuts>,
}

impl Clone for SubstratumMockNode {
    fn clone(&self) -> Self {
        SubstratumMockNode {
            control_stream: RefCell::new (self.control_stream.borrow ().try_clone ().unwrap ()),
            guts: Rc::clone (&self.guts)
        }
    }
}

impl SubstratumNode for SubstratumMockNode {

    fn name(&self) -> &str {
        self.guts.name.as_str ()
    }

    fn node_reference(&self) -> NodeReference {
        NodeReference::new (self.cryptde ().public_key (), self.node_addr ().ip_addr (), self.node_addr ().ports ())
    }

    fn public_key(&self) -> Key {
        self.cryptde ().public_key ()
    }

    fn ip_address(&self) -> IpAddr {
        self.guts.node_addr.ip_addr ()
    }

    fn port_list(&self) -> Vec<u16> {
        self.guts.node_addr.ports().clone ()
    }

    fn node_addr(&self) -> NodeAddr {
        self.guts.node_addr.clone ()
    }

    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr {
        SubstratumNodeUtils::socket_addr (&self.node_addr (), port_selector, self.name ())
    }

    fn make_client(&self, _port: u16) -> SubstratumNodeClient {
        unimplemented!()
    }
}

impl SubstratumMockNode {
    pub fn start(ports: Vec<u16>, index: usize, host_node_parent_dir: Option<String>) -> SubstratumMockNode {
        let node_addr = NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(172, 18, 1, index as u8)), &ports);
        let name = format!("mock_node_{}", index);
        SubstratumNodeUtils::clean_up_existing_container(&name[..]);
        Self::do_docker_run(&node_addr, host_node_parent_dir, &name);
        let wait_addr = SocketAddr::new(node_addr.ip_addr(), CONTROL_STREAM_PORT);
        let control_stream = RefCell::new(Self::wait_for_startup(wait_addr, &name));
        let mut cryptde = Box::new(CryptDENull::new());
        cryptde.generate_key_pair();
        let framer = RefCell::new(DataHunkFramer::new());
        let guts = Rc::new (SubstratumMockNodeGuts {name, node_addr, cryptde, framer});
        SubstratumMockNode {control_stream, guts}
    }

    pub fn transmit_data(&self, data_hunk: DataHunk) -> Result<(), io::Error> {
        let to_transmit: Vec<u8> = data_hunk.into();
        match self.control_stream.borrow_mut().write(&to_transmit[..]) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn transmit_package(&self, transmit_port: u16, package: IncipientCoresPackage, masquerader: &Masquerader, target_key: &Key, target_addr: SocketAddr) -> Result<(), io::Error> {
        let (lcp, _) = LiveCoresPackage::from_incipient(package, self.cryptde ());
        let lcp_data = serde_cbor::ser::to_vec(&lcp).unwrap();
        let encrypted_data = self.cryptde ().encode(target_key, &PlainData::new(&lcp_data[..])).unwrap();
        let masked_data = masquerader.mask(&encrypted_data.data[..]).unwrap();
        let data_hunk = DataHunk::new(SocketAddr::new(self.ip_address(), transmit_port), target_addr, masked_data);
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
                    return Ok(data_hunk)
                },
                None => {
                    match control_stream.read(&mut buf) {
                        Err(ref e) if indicates_dead_stream(e.kind()) => panic!("Couldn't read control stream from {}: {}", self.name(), e),
                        Err(e) => {
                            println!("No data from {} after {:?}", self.name(), timeout);
                            return Err(e)
                        },
                        Ok(0) => panic!("{} dropped its control stream", self.name()),
                        Ok(len) => framer.add_data(&buf[..len]),
                    }
                },
            }
        }
    }

    pub fn wait_for_package(&self, masquerader: &Masquerader, timeout: Duration) -> Result<(SocketAddr, SocketAddr, LiveCoresPackage), io::Error> {
        let data_hunk = self.wait_for_data(timeout)?;
        let unmasked_data = masquerader.try_unmask(&data_hunk.data[..]).unwrap().chunk;
        let decrypted_data = self.cryptde ().decode(&CryptData::new(&unmasked_data[..])).unwrap();
        let lcp = serde_cbor::de::from_slice::<LiveCoresPackage>(&decrypted_data.data[..]).unwrap();
        Ok((data_hunk.from, data_hunk.to, lcp))
    }

    pub fn cryptde(&self) -> &CryptDE {
        self.guts.cryptde.as_ref()
    }

    fn do_docker_run(node_addr: &NodeAddr, host_node_parent_dir: Option<String>,
                     name: &String) {
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
        let mut docker_args = Command::strings(vec!("run", "--detach", "--ip",
                                                    ip_addr_string.as_str(), "--name", name_string.as_str(),
                                                    "--net", "integration_net", "-v", v_param.as_str(), "test_node_image",
                                                    "/node_root/node/MockNode"));
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
                    break
                },
                Err(e) => {
                    println!("{} not yet started on {}: {}", name, wait_addr, e);
                    ()
                },
            }
            retries -= 1;
            if retries <= 0 { break }
            thread::sleep(Duration::from_millis(100))
        }
        if retries <= 0 { panic!("Timed out trying to contact {}", name) }
        stream.unwrap()
    }

    fn make_node_args(node_addr: &NodeAddr) -> Vec<String> {
        vec!(format!("{}", node_addr))
    }
}

struct SubstratumMockNodeGuts {
    name: String,
    node_addr: NodeAddr,
    cryptde: Box<CryptDE>,
    framer: RefCell<DataHunkFramer>,
}

impl Drop for SubstratumMockNodeGuts {
    fn drop(&mut self) {
        SubstratumNodeUtils::stop (self.name.as_str ());
    }
}
