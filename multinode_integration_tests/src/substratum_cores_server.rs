// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::substratum_node::NodeReference;
use crate::substratum_node_cluster::SubstratumNodeCluster;
use node_lib::discriminator::Discriminator;
use node_lib::discriminator::DiscriminatorFactory;
use node_lib::discriminator::UnmaskedChunk;
use node_lib::hopper::live_cores_package::LiveCoresPackage;
use node_lib::http_request_start_finder::HttpRequestDiscriminatorFactory;
use node_lib::json_discriminator_factory::JsonDiscriminatorFactory;
use node_lib::sub_lib::cryptde::CryptDE;
use node_lib::sub_lib::cryptde::CryptData;
use node_lib::sub_lib::cryptde::PrivateKey;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::test_utils::find_free_port;
use node_lib::tls_discriminator_factory::TlsDiscriminatorFactory;
use serde_cbor;
use std::cell::RefCell;
use std::io;
use std::io::Read;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

// TODO: Cover this with tests and put it in the production tree.
pub struct DiscriminatorCluster {
    discriminators: Vec<Discriminator>,
}

impl DiscriminatorCluster {
    pub fn new(factories: Vec<Box<dyn DiscriminatorFactory>>) -> DiscriminatorCluster {
        DiscriminatorCluster {
            discriminators: factories.into_iter().map(|x| x.make()).collect(),
        }
    }

    pub fn add_data(&mut self, data: &[u8]) {
        self.discriminators
            .iter_mut()
            .for_each(|x| x.add_data(data))
    }

    pub fn take_chunk(&mut self) -> Option<UnmaskedChunk> {
        let mut chunks: Vec<UnmaskedChunk> = self
            .discriminators
            .iter_mut()
            .flat_map(|x| x.take_chunk())
            .collect();
        if chunks.len() == 0 {
            None
        } else {
            Some(chunks.remove(0))
        }
    }
}

pub struct SubstratumCoresServer {
    discriminators: RefCell<DiscriminatorCluster>,
    cryptde: CryptDENull,
    io_receiver: Receiver<io::Result<Vec<u8>>>,
    socket_addr: SocketAddr,
    _join_handle: JoinHandle<()>,
}

impl SubstratumCoresServer {
    pub fn new(chain_id: u8) -> SubstratumCoresServer {
        let ip_address = Self::find_local_integration_net_ip_address();
        let port = find_free_port();
        let local_addr = SocketAddr::new(ip_address, port);
        let listener = TcpListener::bind(local_addr)
            .expect(format!("Couldn't start server on {}", local_addr).as_str());
        let cryptde = CryptDENull::new(chain_id);
        let (io_tx, io_rx) = mpsc::channel::<io::Result<Vec<u8>>>();
        let join_handle = thread::spawn(move || loop {
            let (mut stream, _) = match listener.accept() {
                Err(e) => {
                    eprintln!("Error accepting connection to {}: {:?}", local_addr, &e);
                    io_tx.send(Err(e)).unwrap();
                    return;
                }
                Ok(p) => p,
            };
            let peer_addr = stream.peer_addr().unwrap();
            let mut buf = [0u8; 16384];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        eprintln!("TcpStream local {} / remote {}", local_addr, peer_addr);
                        break;
                    }
                    Ok(size) => {
                        let mut bytes = buf.to_vec();
                        bytes.truncate(size);
                        eprintln!(
                            "Received {} bytes from local {} / remote {}: {:?}",
                            size, local_addr, peer_addr, bytes
                        );
                        io_tx.send(Ok(bytes)).unwrap();
                    }
                    Err(e) => {
                        eprintln!(
                            "Error reading from stream local {} / remote {}: {:?}",
                            local_addr, peer_addr, &e
                        );
                        io_tx.send(Err(e)).unwrap();
                    }
                };
            }
        });
        thread::sleep(Duration::from_millis(100));
        SubstratumCoresServer {
            discriminators: RefCell::new(DiscriminatorCluster::new(Self::default_factories())),
            cryptde,
            io_receiver: io_rx,
            socket_addr: local_addr,
            _join_handle: join_handle,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    pub fn node_reference(&self) -> NodeReference {
        NodeReference {
            public_key: self.cryptde.public_key().clone(),
            node_addr_opt: Some(NodeAddr::new(
                &self.socket_addr.ip(),
                &vec![self.socket_addr.port()],
            )),
        }
    }

    pub fn cryptde<'a>(&'a self) -> &'a dyn CryptDE {
        &self.cryptde
    }

    pub fn public_key(&self) -> PublicKey {
        self.node_reference().public_key.clone()
    }

    pub fn node_addr_opt(&self) -> Option<NodeAddr> {
        self.node_reference().node_addr_opt.clone()
    }

    pub fn private_key(&self) -> &PrivateKey {
        self.cryptde().private_key()
    }

    pub fn wait_for_package(&self, timeout: Duration) -> LiveCoresPackage {
        let chunk = self.get_next_chunk(timeout);
        let decoded_chunk = self
            .cryptde
            .decode(&CryptData::new(&chunk.chunk[..]))
            .unwrap();
        serde_cbor::de::from_slice::<LiveCoresPackage>(decoded_chunk.as_slice())
            .expect(format!("Error deserializing LCP from {:?}", chunk.chunk).as_str())
    }

    fn default_factories() -> Vec<Box<dyn DiscriminatorFactory>> {
        vec![
            Box::new(JsonDiscriminatorFactory::new()),
            Box::new(HttpRequestDiscriminatorFactory::new()),
            Box::new(TlsDiscriminatorFactory::new()),
        ]
    }

    fn find_local_integration_net_ip_address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(
            172,
            18,
            0,
            if SubstratumNodeCluster::is_in_jenkins() {
                2
            } else {
                1
            },
        ))
    }

    fn get_next_chunk(&self, timeout: Duration) -> UnmaskedChunk {
        let mut discriminators = self.discriminators.borrow_mut();
        match discriminators.take_chunk() {
            None => (),
            Some(chunk) => return chunk,
        }
        loop {
            match self.io_receiver.recv_timeout(timeout) {
                Err(e) => panic!("{:?}", e),
                Ok(result) => match result {
                    Err(e) => panic!("{:?}", e),
                    Ok(buf) => {
                        println!("got some buf: {:?}", buf);
                        discriminators.add_data(&buf[..])
                    }
                },
            }
            match discriminators.take_chunk() {
                None => (),
                Some(chunk) => return chunk,
            }
        }
    }
}
