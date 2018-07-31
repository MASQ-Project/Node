// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use sub_lib::hopper::ExpiredCoresPackage;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::TcpListener;
use serde_cbor;
use hopper_lib::hopper::LiveCoresPackage;
use sub_lib::cryptde::CryptDE;
use std::io;
use std::io::Read;
use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use node_lib::discriminator::Discriminator;
use node_lib::discriminator::DiscriminatorFactory;
use node_lib::discriminator::UnmaskedChunk;
use std::net::Ipv4Addr;
use std::io::ErrorKind;

// TODO: Cover this with tests and put it in the production tree.
pub struct DiscriminatorCluster {
    discriminators: Vec<Discriminator>,
}

impl DiscriminatorCluster {
    pub fn new (factories: Vec<Box<DiscriminatorFactory>>) -> DiscriminatorCluster {
        DiscriminatorCluster {
            discriminators: factories.into_iter ().map (|x| x.make ()).collect ()
        }
    }

    pub fn add_data (&mut self, data: &[u8]) {
        self.discriminators.iter_mut ().for_each (|x| x.add_data (data))
    }

    pub fn take_chunk (&mut self) -> Option<UnmaskedChunk> {
        let mut chunks: Vec<UnmaskedChunk> = self.discriminators.iter_mut ().flat_map (|x| x.take_chunk ()).collect ();
        if chunks.len () == 0 {
            None
        }
        else {
            Some (chunks.remove (0))
        }
    }
}

pub struct SubstratumCoresServer<'a> {
    discriminators: DiscriminatorCluster,
    cryptde: &'a CryptDE,
    io_receiver: Receiver<io::Result<Vec<u8>>>,
    socket_addr: SocketAddr,
    _join_handle: JoinHandle<()>,
}

impl<'a> SubstratumCoresServer<'a> {
    fn try_bind (port: u16) -> Option<TcpListener> {
        for mut last_byte in 1..10 {
            let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 18, 0, last_byte)), port);
            match TcpListener::bind(socket_addr) {
                Err(ref e) if e.kind() == ErrorKind::AddrNotAvailable => continue,
                Err(e) => panic!("Could not bind {}: {:?}", socket_addr, e),
                Ok(listener) => return Some(listener)
            }
        }
        return None
    }

    pub fn new(port: u16, factories: Vec<Box<DiscriminatorFactory>>, cryptde: &'a CryptDE) -> SubstratumCoresServer<'a> {
        let listener = SubstratumCoresServer::try_bind(port).expect("Couldn't start server on 172.18.0.x where x was somewhere between 1 and 10");
        let socket_addr = listener.local_addr ().unwrap ();

        let (io_tx, io_rx) = mpsc::channel::<io::Result<Vec<u8>>>();
        let join_handle = thread::spawn (move || {
            let (mut stream, _) = match listener.accept () {
                Err (e) => {
                    eprintln! ("Error accepting connection: {:?}", &e);
                    io_tx.send (Err (e)).unwrap ();
                    return
                }
                Ok (p) => p
            };
            let mut buf = [0u8; 16384];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        break
                    },
                    Ok(size) => {
                        let mut bytes = buf.to_vec ();
                        bytes.truncate (size);
                        io_tx.send (Ok(bytes)).unwrap ();
                    },
                    Err(e) => {
                        eprintln! ("Error reading from stream: {:?}", &e);
                        io_tx.send (Err (e)).unwrap ();
                    },
                };
            }
        });
        thread::sleep (Duration::from_millis (1000));
        SubstratumCoresServer {
            discriminators: DiscriminatorCluster::new (factories),
            cryptde,
            io_receiver: io_rx,
            socket_addr,
            _join_handle: join_handle,
        }
    }

    pub fn local_addr (&self) -> SocketAddr {
        self.socket_addr
    }

    pub fn wait_for_package(&mut self) -> ExpiredCoresPackage {
        let chunk = self.get_next_chunk ();
        let live_cores_package = serde_cbor::de::from_slice::<LiveCoresPackage> (&chunk.chunk[..]).expect (format! ("Error deserializing LCP from {:?}", chunk.chunk).as_str ());
        live_cores_package.to_expired (self.cryptde)
    }

    fn get_next_chunk (&mut self) -> UnmaskedChunk {
        match self.discriminators.take_chunk () {
            None => (),
            Some (chunk) => return chunk
        }
        loop {
            println! ("Test server waiting for data from client");
            match self.io_receiver.recv () {
                Err (e) => panic! ("{:?}", e),
                Ok (result) => match result {
                    Err(e) => panic!("{:?}", e),
                    Ok(buf) => self.discriminators.add_data(&buf[..]),
                }
            }
            match self.discriminators.take_chunk () {
                None => (),
                Some (chunk) => return chunk
            }
        }
    }
}
