// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg (test)]
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::time::SystemTime;
use std::time::Duration;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;
use std::marker::Sync;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::ops::DerefMut;
use std::borrow::BorrowMut;
use std::str::FromStr;
use sub_lib;
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::test_utils::TestLog;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::DispatcherClient;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::PeerClients;
use sub_lib::dispatcher::TransmitterHandle;
use sub_lib::logger::Logger;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::neighborhood::NeighborhoodError;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;
use sub_lib::actor_messages::ExpiredCoresPackageMessage;
use sub_lib::framer::Framer;
use sub_lib::framer::FramedChunk;
use masquerader::Masquerader;
use masquerader::MasqueradeError;
use null_masquerader::NullMasquerader;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;
use actix::Subscriber;

pub trait TestLogOwner {
    fn get_test_log (&self) -> Arc<Mutex<TestLog>>;
}

pub fn extract_log<T> (owner: T) -> (T, Arc<Mutex<TestLog>>) where T: TestLogOwner {
    let test_log = owner.get_test_log ();
    (owner, test_log)
}

pub struct TcpStreamWrapperMock {
    pub log: Arc<Mutex<TestLog>>,
    pub peer_addr_result: io::Result<SocketAddr>,
    pub set_read_timeout_results: RefCell<Vec<io::Result<()>>>,
    pub read_results: Vec<(Vec<u8>, io::Result<usize>)>,
    pub connect_results: Vec<io::Result<()>>,
    pub write_params: Arc<Mutex<Vec<Vec<u8>>>>,
    pub write_results: Vec<io::Result<usize>>,
    pub shutdown_results: RefCell<Vec<io::Result<()>>>,
    pub try_clone_results: RefCell<Vec<io::Result<Box<TcpStreamWrapper>>>>,
    pub name: String
}

pub struct TcpStreamWrapperMockHandle {
    pub log: Arc<Mutex<TestLog>>,
    pub write_params: Arc<Mutex<Vec<Vec<u8>>>>
}

impl io::Read for TcpStreamWrapperMock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.log.lock ().unwrap ().log (format! ("read ({}-byte buf)", buf.len ()));
        let pair = self.read_results.remove (0);
        let data = pair.0;
        let result = pair.1;
        let utf8 = String::from_utf8 (data.clone ());
        if utf8.is_ok () && (utf8.expect ("Internal error") == String::from ("block")) {
            let (_tx, rx) = mpsc::channel::<usize> ();
            rx.recv ().unwrap (); // block here; don't continue
            Ok (5) // compiler candy: never executed
        }
        else {
            for i in 0..data.len() {
                buf[i] = data[i]
            }
            result
        }
    }
}

impl io::Write for TcpStreamWrapperMock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_params.borrow_mut().lock ().unwrap ().push (Vec::from (buf));
        self.write_results.remove (0)
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

impl TcpStreamWrapper for TcpStreamWrapperMock {
    fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.log.lock ().unwrap ().log (format! ("connect ({:?})", addr));
        self.connect_results.remove (0)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self.peer_addr_result {
            Ok (socket_addr) => Ok (socket_addr.clone ()),
            Err (ref e) => Err (Error::from (e.kind ()))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Skinny implementation
        Ok (SocketAddr::from_str ("2.3.4.5:6789").unwrap ())
    }

    fn set_read_timeout(&self, duration: Option<Duration>) -> io::Result<()> {
        self.log.lock ().unwrap ().log (format! ("set_read_timeout ({:?})", duration));
        self.set_read_timeout_results.borrow_mut ().deref_mut ().remove (0)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.log.lock ().unwrap ().log (format! ("shutdown ({:?})", how));
        self.shutdown_results.borrow_mut ().deref_mut ().remove (0)
    }

    fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {unimplemented!()}
    fn read_timeout(&self) -> io::Result<Option<Duration>> {unimplemented!()}
    fn write_timeout(&self) -> io::Result<Option<Duration>> {unimplemented!()}
    fn peek(&self, _buf: &mut [u8]) -> io::Result<usize> {unimplemented!()}
    fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {unimplemented!()}
    fn nodelay(&self) -> io::Result<bool> {unimplemented!()}
    fn set_ttl(&self, _ttl: u32) -> io::Result<()> {unimplemented!()}
    fn ttl(&self) -> io::Result<u32> {unimplemented!()}
    fn take_error(&self) -> io::Result<Option<io::Error>> {unimplemented!()}
    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {unimplemented!()}
    fn try_clone (&self) -> io::Result<Box<TcpStreamWrapper>> {
        self.log.lock ().unwrap ().log (format! ("try_clone ()"));
        self.try_clone_results.borrow_mut ().deref_mut ().remove (0)
    }
}

impl TestLogOwner for TcpStreamWrapperMock {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>> {self.log.clone ()}
}

impl TcpStreamWrapperMock {
    pub fn new () -> TcpStreamWrapperMock {
        TcpStreamWrapperMock {
            log: Arc::new (Mutex::new (TestLog::new ())),
            peer_addr_result: Err (Error::from (ErrorKind::Other)),
            set_read_timeout_results: RefCell::new (vec! ()),
            read_results: vec! (),
            connect_results: vec! (),
            write_params: Arc::new (Mutex::new (vec! ())),
            write_results: vec! (),
            shutdown_results: RefCell::new (vec! ()),
            try_clone_results: RefCell::new (vec! ()),
            name: String::from ("unknown")
        }
    }

    #[allow (dead_code)]
    pub fn name (mut self, name: &str) -> TcpStreamWrapperMock {
        self.name = String::from (name);
        self
    }

    #[allow (dead_code)]
    pub fn make_handle (&self) -> TcpStreamWrapperMockHandle {
        TcpStreamWrapperMockHandle {
            log: self.log.clone (),
            write_params: self.write_params.clone ()
        }
    }
}

pub struct DispatcherClientNull {
    pub name: String,
    log: Arc<Mutex<TestLog>>,
    transmitter_handle: Option<Box<TransmitterHandle>>,
    logger: Option<Logger>
}

impl DispatcherClient for DispatcherClientNull {
    fn bind(&mut self, transmitter_handle: Box<TransmitterHandle>, _clients: &PeerClients) {
        self.log.lock ().unwrap ().log (format! ("bind (...)"));
        self.transmitter_handle = Some (transmitter_handle);
        self.logger = Some (Logger::new (&self.name[..]));
    }

    fn receive(&mut self, source: Endpoint, data: PlainData) {
        self.log.lock ().unwrap ().log (format! ("receive ('{:?}', '{}'", source, to_string (&data.data)));
        self.logger.as_ref ().unwrap ().log (format! ("receive (...)"));
    }
}

unsafe impl Sync for DispatcherClientNull {}

impl TestLogOwner for DispatcherClientNull {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>> {self.log.clone ()}
}

impl DispatcherClientNull {
    pub fn new (name: &str) -> DispatcherClientNull {
        DispatcherClientNull {
            name: String::from (name),
            log: Arc::new (Mutex::new (TestLog::new ())),
            transmitter_handle: None,
            logger: None
        }
    }
}

pub struct NeighborhoodNull {
    pub delegate: DispatcherClientNull,
    pub bound: bool,
    pub translation_triples: Vec<(IpAddr, Vec<u16>, Vec<u8>)>
}

impl NeighborhoodNull {
    pub fn new (translation_triples: Vec<(&str, &[u16], &str)>) -> NeighborhoodNull {
        let real_translation_triples = translation_triples.iter ().map (|triple| {
            let (str_ip, ports, str_key) = *triple;
            (IpAddr::from_str (str_ip).unwrap (), Vec::from (ports), Vec::from (str_key.as_bytes ()))
        }).collect ();
        NeighborhoodNull {
            delegate: DispatcherClientNull::new ("neighborhood"),
            bound: false,
            translation_triples: real_translation_triples
        }
    }
}

impl Neighborhood for NeighborhoodNull {
    fn route_one_way(&mut self, _destination: &Key, _remote_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn route_round_trip(&mut self, _destination: &Key, _remote_recipient: Component, _local_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn public_key_from_ip_address(&self, ip_addr: &IpAddr) -> Option<Key> {
        assert_eq! (self.bound, true);
        self.delegate.log.lock ().unwrap ().log (format! ("public_key_from_ip_address ({:?})", ip_addr));
        match &self.translation_triples.iter ().find (|triple| {triple.0 == *ip_addr}) {
            &Some (ref triple) => Some (Key::new (&triple.2.clone ()[..])),
            &None => None
        }
    }

    fn node_addr_from_public_key(&self, public_key: &[u8]) -> Option<NodeAddr> {
        assert_eq! (self.bound, true);
        self.delegate.log.lock ().unwrap ().log (format! ("socket_addrs_from_public_key ({:?})", public_key));
        match &self.translation_triples.iter ().find (|triple| {triple.2 == public_key}) {
            &Some (ref triple) => Some (NodeAddr::new (&triple.0, &triple.1)),
            &None => None
        }
    }

    fn node_addr_from_ip_address(&self, ip_addr: &IpAddr) -> Option<NodeAddr> {
        assert_eq! (self.bound, true);
        self.delegate.log.lock ().unwrap ().log (format! ("socket_addrs_from_ip_address ({:?})", ip_addr));
        match &self.translation_triples.iter ().find (|triple| {triple.0 == *ip_addr}) {
            &Some (ref triple) => Some(NodeAddr::new(&triple.0, &triple.1)),
            &None => None
        }
    }
}

impl DispatcherClient for NeighborhoodNull {
    fn bind(&mut self, transmitter_handle: Box<TransmitterHandle>, clients: &PeerClients) {
        self.bound = true;
        self.delegate.bind (transmitter_handle, clients);
    }

    fn receive(&mut self, source: Endpoint, data: PlainData) {
        self.delegate.receive (source, data);
    }
}

impl TestLogOwner for NeighborhoodNull {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>> {self.delegate.log.clone ()}
}

pub struct MasqueraderMock {
    log: Arc<Mutex<TestLog>>,
    try_unmask_results: RefCell<Vec<Option<(Component, Vec<u8>)>>>,
    mask_results: RefCell<Vec<Result<Vec<u8>, MasqueradeError>>>
}

impl Masquerader for MasqueraderMock {
    fn try_unmask(&self, item: &[u8]) -> Option<(Component, Vec<u8>)> {
        self.log.lock ().unwrap ().log (format! ("try_unmask (\"{}\")", String::from_utf8 (Vec::from (item)).unwrap ()));
        self.try_unmask_results.borrow_mut ().remove (0)
    }

    fn mask(&self, component: Component, data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        self.log.lock ().unwrap ().log (format! ("mask ({:?}, \"{}\")", component, String::from_utf8 (Vec::from (data)).unwrap ()));
        self.mask_results.borrow_mut ().remove (0)
    }
}

impl TestLogOwner for MasqueraderMock {
    fn get_test_log(&self) -> Arc<Mutex<TestLog>> {
        self.log.clone ()
    }
}

impl MasqueraderMock {
    #[allow (dead_code)]
    pub fn new () -> MasqueraderMock {
        MasqueraderMock {
            log: Arc::new (Mutex::new (TestLog::new ())),
            try_unmask_results: RefCell::new (Vec::new ()),
            mask_results: RefCell::new (Vec::new ())
        }
    }

    #[allow (dead_code)]
    pub fn add_try_unmask_result (&mut self, result: Option<(Component, Vec<u8>)>) {
        self.try_unmask_results.borrow_mut ().push (result);
    }

    #[allow (dead_code)]
    pub fn add_mask_result (&mut self, result: Result<Vec<u8>, MasqueradeError>) {
        self.mask_results.borrow_mut ().push (result);
    }
}

pub fn wait_until<F> (check: F) where F: Fn() -> bool {
    let now = SystemTime::now ();
    while !check () {
        if now.elapsed ().unwrap ().as_secs () >= 1 {
            panic! ("Waited for more than a second")
        }
        thread::sleep (Duration::from_millis (10))
    }
}

pub fn to_string (data: &Vec<u8>) -> String {
    match String::from_utf8 (data.clone ()) {
        Ok (data_string) => format! ("{}", data_string),
        Err (_) => format! ("{:?}", data)
    }
}

pub struct NullFramer {
    data: Vec<Vec<u8>>
}

impl Framer for NullFramer {
    fn add_data(&mut self, data: &[u8]) {
        self.data.push (Vec::from (data));
    }

    fn take_frame(&mut self) -> Option<FramedChunk> {
        if self.data.is_empty () {None} else {Some (FramedChunk {chunk: self.data.remove (0), last_chunk: true})}
    }
}

pub fn make_null_discriminator (component: Component, data: Vec<Vec<u8>>) -> Discriminator {
    let framer = NullFramer {data};
    let masquerader = NullMasquerader::new (component);
    Discriminator::new (Box::new (framer), vec! (Box::new (masquerader)))
}

pub struct NullDiscriminatorFactory {
    discriminator_natures: RefCell<Vec<(Component, Vec<Vec<u8>>)>>
}

impl DiscriminatorFactory for NullDiscriminatorFactory {
    fn make(&self) -> Box<Discriminator> {
        let (component, data) = self.discriminator_natures.borrow_mut ().remove (0);
        Box::new (make_null_discriminator(component, data))
    }

    fn clone(&self) -> Box<DiscriminatorFactory> {
        unimplemented!()
    }
}

impl NullDiscriminatorFactory {
    pub fn new () -> NullDiscriminatorFactory {
        NullDiscriminatorFactory {
            discriminator_natures: RefCell::new (vec! ())
        }
    }

    pub fn discriminator_nature (self, component: Component, data: Vec<Vec<u8>>) -> NullDiscriminatorFactory {
        self.discriminator_natures.borrow_mut ().push ((component, data));
        self
    }
}
