// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::cell::RefCell;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use resolver_wrapper::ResolverWrapper;
use resolver_wrapper::ResolverWrapperFactory;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::tcp_wrappers::TcpStreamWrapperFactory;
use std::net::IpAddr;
use tokio_core::reactor::Handle;
use futures::future;
use futures::sync::mpsc::SendError;
use futures::sync::mpsc::unbounded;
use trust_dns_resolver::error::ResolveError;
use tokio_core::reactor::CoreId;
use trust_dns_resolver::lookup::Lookup;
use trust_dns_proto::rr::RData;
use std::io::ErrorKind;
use resolver_wrapper::WrappedLookupIpFuture;

pub struct TcpStreamWrapperFactoryMock {
    tcp_stream_wrappers: Arc<Mutex<Vec<TcpStreamWrapperMock>>>
}

impl TcpStreamWrapperFactory for TcpStreamWrapperFactoryMock {
    fn make(&self) -> Box<TcpStreamWrapper> {
        Box::new (self.tcp_stream_wrappers.lock ().unwrap ().remove (0))
    }

    fn dup(&self) -> Box<TcpStreamWrapperFactory> {
        Box::new (TcpStreamWrapperFactoryMock {
            tcp_stream_wrappers: self.tcp_stream_wrappers.clone ()
        })
    }
}

impl TcpStreamWrapperFactoryMock {
    pub fn new () -> TcpStreamWrapperFactoryMock {
        TcpStreamWrapperFactoryMock {
            tcp_stream_wrappers: Arc::new (Mutex::new (Vec::new ())),
        }
    }

    pub fn tcp_stream_wrapper (self, tcp_stream_wrapper: TcpStreamWrapperMock) -> TcpStreamWrapperFactoryMock {
        self.tcp_stream_wrappers.lock ().unwrap ().push (tcp_stream_wrapper);
        self
    }
}

struct TcpStreamWrapperMockResults {
    connect_results: Vec<io::Result<()>>,
    try_clone_results: Vec<io::Result<Box<TcpStreamWrapper>>>,
    peer_addr_result: io::Result<SocketAddr>,
    write_results: Vec<io::Result<usize>>,
    read_buffers: Vec<Vec<u8>>,
    read_results: Vec<io::Result<usize>>,
    read_delay: u64,
    shutdown_results: Vec<io::Result<()>>,
    set_read_timeout_results: Vec<io::Result<()>>,
}

pub struct TcpStreamWrapperMock {
    mocked_try_clone: bool,
    connect_parameters: Arc<Mutex<Vec<SocketAddr>>>,
    write_parameters: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown_parameters: Arc<Mutex<Vec<Shutdown>>>,
    set_read_timeout_parameters: Arc<Mutex<Vec<Option<Duration>>>>,
    results: Arc<Mutex<TcpStreamWrapperMockResults>>,
}

impl Clone for TcpStreamWrapperMock {
    fn clone(&self) -> Self {
        TcpStreamWrapperMock {
            mocked_try_clone: self.mocked_try_clone,
            connect_parameters: self.connect_parameters.clone (),
            write_parameters: self.write_parameters.clone (),
            shutdown_parameters: self.shutdown_parameters.clone (),
            set_read_timeout_parameters: self.set_read_timeout_parameters.clone (),
            results: self.results.clone (),
        }
    }
}

impl TcpStreamWrapper for TcpStreamWrapperMock {
    fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.connect_parameters.lock ().unwrap ().push (addr);
        self.results.lock ().unwrap ().connect_results.remove (0)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        let guts = self.results.lock ().unwrap ();
        match &guts.peer_addr_result {
            &Ok (ref x) => Ok (x.clone ()),
            &Err (ref e) => Err (io::Error::from (e.kind ()))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> { unimplemented!() }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown_parameters.lock ().unwrap ().push (how);
        self.results.lock ().unwrap ().shutdown_results.remove (0)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout_parameters.lock ().unwrap ().push (dur);
        self.results.lock ().unwrap ().set_read_timeout_results.remove (0)
    }

    fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> { unimplemented!() }
    fn read_timeout(&self) -> io::Result<Option<Duration>> { unimplemented!() }
    fn write_timeout(&self) -> io::Result<Option<Duration>> { unimplemented!() }
    fn peek(&self, _buf: &mut [u8]) -> io::Result<usize> { unimplemented!() }
    fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> { unimplemented!() }
    fn nodelay(&self) -> io::Result<bool> { unimplemented!() }
    fn set_ttl(&self, _ttl: u32) -> io::Result<()> { unimplemented!() }
    fn ttl(&self) -> io::Result<u32> { unimplemented!() }
    fn take_error(&self) -> io::Result<Option<io::Error>> { unimplemented!() }
    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> { unimplemented!() }
    fn try_clone(&self) -> io::Result<Box<TcpStreamWrapper>> {
        if self.mocked_try_clone {
            let mut guts = self.results.lock().unwrap();
            guts.try_clone_results.remove(0)
        }
        else {
            Ok (Box::new (self.clone ()))
        }
    }
}

impl Read for TcpStreamWrapperMock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut results = self.results.lock ().unwrap ();
        thread::sleep (Duration::from_millis (results.read_delay));
        if results.read_buffers.len () > 0 {
            let chunk = results.read_buffers.remove(0);
            for index in 0..chunk.len() { buf[index] = chunk[index] }
        }

        if results.read_results.is_empty() {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        } else {
            results.read_results.remove (0)
        }
    }
}

impl Write for TcpStreamWrapperMock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_parameters.lock ().unwrap ().push (Vec::from (buf));
        self.results.lock ().unwrap ().write_results.remove (0)
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

#[allow (dead_code)]
impl TcpStreamWrapperMock {
    pub fn new () -> TcpStreamWrapperMock {
        TcpStreamWrapperMock {
            mocked_try_clone: true,
            connect_parameters: Arc::new (Mutex::new (vec! ())),
            write_parameters: Arc::new (Mutex::new (vec! ())),
            shutdown_parameters: Arc::new (Mutex::new (vec! ())),
            set_read_timeout_parameters: Arc::new (Mutex::new (vec! ())),
            results: Arc::new (Mutex::new (TcpStreamWrapperMockResults {
                connect_results: vec!(),
                try_clone_results: vec!(),
                peer_addr_result: Err (io::Error::from (ErrorKind::Other)),
                read_buffers: vec!(),
                read_results: vec!(),
                read_delay: 0,
                write_results: vec!(),
                shutdown_results: vec!(),
                set_read_timeout_results: vec!(),
            }))
        }
    }

    pub fn connect_result (self, result: io::Result<()>) -> TcpStreamWrapperMock {
        self.results.lock ().unwrap ().connect_results.push (result);
        self
    }

    pub fn connect_parameters (mut self, parameters: &Arc<Mutex<Vec<SocketAddr>>>) -> TcpStreamWrapperMock {
        self.connect_parameters = parameters.clone ();
        self
    }

    pub fn write_result (self, result: io::Result<usize>) -> TcpStreamWrapperMock {
        self.results.lock ().unwrap ().write_results.push (result);
        self
    }

    pub fn write_parameters (mut self, parameters: &Arc<Mutex<Vec<Vec<u8>>>>) -> TcpStreamWrapperMock {
        self.write_parameters = parameters.clone ();
        self
    }

    pub fn read_buffer (self, buffer: Vec<u8>) -> TcpStreamWrapperMock {
        self.results.lock ().unwrap ().read_buffers.push (buffer);
        self
    }

    pub fn read_result (self, result: io::Result<usize>) -> TcpStreamWrapperMock {
        self.results.lock ().unwrap ().read_results.push (result);
        self
    }

    pub fn shutdown_result (self, result: io::Result<()>) -> TcpStreamWrapperMock {
        self.results.lock ().unwrap ().shutdown_results.push (result);
        self
    }

    pub fn shutdown_parameters (mut self, parameters: &Arc<Mutex<Vec<Shutdown>>>) -> TcpStreamWrapperMock {
        self.shutdown_parameters = parameters.clone ();
        self
    }

    pub fn set_read_timeout_result (self, result: io::Result<()>) -> TcpStreamWrapperMock {
        self.results.lock ().unwrap ().set_read_timeout_results.push (result);
        self
    }

    pub fn set_read_timeout_parameters (mut self, parameters: &Arc<Mutex<Vec<Option<Duration>>>>) -> TcpStreamWrapperMock {
        self.set_read_timeout_parameters = parameters.clone ();
        self
    }
}

pub struct ResolverWrapperMock {
    lookup_ip_results: RefCell<Vec<Box<WrappedLookupIpFuture>>>,
    lookup_ip_parameters: Arc<Mutex<Vec<String>>>,
}

impl ResolverWrapper for ResolverWrapperMock {
    fn lookup_ip(&self, host: &str) -> Box<WrappedLookupIpFuture> {
        self.lookup_ip_parameters.lock ().unwrap ().push (String::from (host));
        self.lookup_ip_results.borrow_mut ().remove (0)
    }
}

impl ResolverWrapperMock {
    pub fn new () -> ResolverWrapperMock {
        ResolverWrapperMock {
            lookup_ip_results: RefCell::new (vec! ()),
            lookup_ip_parameters: Arc::new (Mutex::new (vec! ())),
        }
    }

    pub fn lookup_ip_success (self, ip_addrs: Vec<IpAddr>) -> ResolverWrapperMock {
        let rdatas: Vec<RData> = ip_addrs.into_iter ().map (|ip_addr| {
            match ip_addr {
                IpAddr::V4 (ip_addr) => RData::A(ip_addr).into (),
                IpAddr::V6 (ip_addr) => RData::AAAA(ip_addr).into ()
            }
        }).collect ();
        let lookup_ip = Lookup::new (Arc::new (rdatas)).into ();
        self.lookup_ip_results.borrow_mut ().push (Box::new (future::ok (lookup_ip)));
        self
    }

    pub fn lookup_ip_failure (self, error: ResolveError) -> ResolverWrapperMock {
        self.lookup_ip_results.borrow_mut ().push (Box::new (future::err (error)));
        self
    }

    pub fn lookup_ip_parameters (mut self, parameters: &Arc<Mutex<Vec<String>>>) -> ResolverWrapperMock {
        self.lookup_ip_parameters = parameters.clone();
        self
    }
}

pub struct ResolverWrapperFactoryMock {
    factory_results: RefCell<Vec<Box<ResolverWrapper>>>,
    factory_parameters: RefCell<Arc<Mutex<Vec<(ResolverConfig, ResolverOpts, CoreId)>>>>
}

impl ResolverWrapperFactory for ResolverWrapperFactoryMock {
    fn make(&self, config: ResolverConfig, options: ResolverOpts, reactor: &Handle) -> Box<ResolverWrapper> {
        let parameters_ref_mut = self.factory_parameters.borrow_mut ();
        let mut parameters_guard = parameters_ref_mut.lock ().unwrap ();
        parameters_guard.push ((config, options, reactor.id ()));
        self.factory_results.borrow_mut ().remove (0)
    }
}

impl ResolverWrapperFactoryMock {
    pub fn new () -> ResolverWrapperFactoryMock {
        ResolverWrapperFactoryMock {
            factory_results: RefCell::new (vec! ()),
            factory_parameters: RefCell::new (Arc::new (Mutex::new (vec! ())))
        }
    }

    pub fn new_result(self, result: Box<ResolverWrapper>) -> ResolverWrapperFactoryMock {
        self.factory_results.borrow_mut ().push (result);
        self
    }

    pub fn new_parameters(self, parameters: &mut Arc<Mutex<Vec<(ResolverConfig, ResolverOpts, CoreId)>>>) -> ResolverWrapperFactoryMock {
        *parameters = self.factory_parameters.borrow_mut ().clone ();
        self
    }
}

pub fn make_send_error<T>(msg: T) -> Result<(), SendError<T>> {
    let (tx, _) = unbounded();
    tx.unbounded_send(msg)
}
