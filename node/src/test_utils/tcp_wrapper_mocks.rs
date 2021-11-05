// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::tcp_wrappers::TcpStreamWrapper;
use crate::sub_lib::tcp_wrappers::TcpStreamWrapperFactory;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Default)]
pub struct TcpStreamWrapperFactoryMock {
    tcp_stream_wrappers: Arc<Mutex<Vec<TcpStreamWrapperMock>>>,
}

impl TcpStreamWrapperFactory for TcpStreamWrapperFactoryMock {
    fn make(&self) -> Box<dyn TcpStreamWrapper> {
        Box::new(self.tcp_stream_wrappers.lock().unwrap().remove(0))
    }

    fn dup(&self) -> Box<dyn TcpStreamWrapperFactory> {
        Box::new(TcpStreamWrapperFactoryMock {
            tcp_stream_wrappers: self.tcp_stream_wrappers.clone(),
        })
    }
}

impl TcpStreamWrapperFactoryMock {
    pub fn new() -> Self {
        Self {
            tcp_stream_wrappers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn tcp_stream_wrapper(
        self,
        tcp_stream_wrapper: TcpStreamWrapperMock,
    ) -> TcpStreamWrapperFactoryMock {
        self.tcp_stream_wrappers
            .lock()
            .unwrap()
            .push(tcp_stream_wrapper);
        self
    }
}

struct TcpStreamWrapperMockResults {
    connect_results: Vec<io::Result<()>>,
    try_clone_results: Vec<io::Result<Box<dyn TcpStreamWrapper>>>,
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
            connect_parameters: self.connect_parameters.clone(),
            write_parameters: self.write_parameters.clone(),
            shutdown_parameters: self.shutdown_parameters.clone(),
            set_read_timeout_parameters: self.set_read_timeout_parameters.clone(),
            results: self.results.clone(),
        }
    }
}

impl TcpStreamWrapper for TcpStreamWrapperMock {
    fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.connect_parameters.lock().unwrap().push(addr);
        self.results.lock().unwrap().connect_results.remove(0)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown_parameters.lock().unwrap().push(how);
        self.results.lock().unwrap().shutdown_results.remove(0)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout_parameters.lock().unwrap().push(dur);
        self.results
            .lock()
            .unwrap()
            .set_read_timeout_results
            .remove(0)
    }

    fn try_clone(&self) -> io::Result<Box<dyn TcpStreamWrapper>> {
        if self.mocked_try_clone {
            let mut guts = self.results.lock().unwrap();
            guts.try_clone_results.remove(0)
        } else {
            Ok(Box::new(self.clone()))
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        let guts = self.results.lock().unwrap();
        match guts.peer_addr_result {
            Ok(ref x) => Ok(*x),
            Err(ref e) => Err(io::Error::from(e.kind())),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        unimplemented!()
    }
    fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        unimplemented!()
    }
    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        unimplemented!()
    }
    fn write_timeout(&self) -> io::Result<Option<Duration>> {
        unimplemented!()
    }
    fn peek(&self, _buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
    fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        unimplemented!()
    }
    fn nodelay(&self) -> io::Result<bool> {
        unimplemented!()
    }
    fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        unimplemented!()
    }
    fn ttl(&self) -> io::Result<u32> {
        unimplemented!()
    }
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        unimplemented!()
    }
    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        unimplemented!()
    }
}

impl Read for TcpStreamWrapperMock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut results = self.results.lock().unwrap();
        thread::sleep(Duration::from_millis(results.read_delay));
        if !results.read_buffers.is_empty() {
            let chunk = results.read_buffers.remove(0);
            buf[..chunk.len()].clone_from_slice(&chunk[..])
        }

        if results.read_results.is_empty() {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        } else {
            results.read_results.remove(0)
        }
    }
}
impl Write for TcpStreamWrapperMock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_parameters.lock().unwrap().push(Vec::from(buf));
        self.results.lock().unwrap().write_results.remove(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

impl Default for TcpStreamWrapperMock {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpStreamWrapperMock {
    pub fn new() -> TcpStreamWrapperMock {
        TcpStreamWrapperMock {
            mocked_try_clone: true,
            connect_parameters: Arc::new(Mutex::new(vec![])),
            write_parameters: Arc::new(Mutex::new(vec![])),
            shutdown_parameters: Arc::new(Mutex::new(vec![])),
            set_read_timeout_parameters: Arc::new(Mutex::new(vec![])),
            results: Arc::new(Mutex::new(TcpStreamWrapperMockResults {
                connect_results: vec![],
                try_clone_results: vec![],
                peer_addr_result: Err(io::Error::from(ErrorKind::Other)),
                read_buffers: vec![],
                read_results: vec![],
                read_delay: 0,
                write_results: vec![],
                shutdown_results: vec![],
                set_read_timeout_results: vec![],
            })),
        }
    }

    pub fn connect_result(self, result: io::Result<()>) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().connect_results.push(result);
        self
    }

    pub fn connect_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<SocketAddr>>>,
    ) -> TcpStreamWrapperMock {
        self.connect_parameters = parameters.clone();
        self
    }

    pub fn write_result(self, result: io::Result<usize>) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().write_results.push(result);
        self
    }

    pub fn write_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> TcpStreamWrapperMock {
        self.write_parameters = parameters.clone();
        self
    }

    pub fn read_buffer(self, buffer: Vec<u8>) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().read_buffers.push(buffer);
        self
    }

    pub fn read_result(self, result: io::Result<usize>) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().read_results.push(result);
        self
    }

    pub fn read_delay(self, milliseconds: u64) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().read_delay = milliseconds;
        self
    }

    pub fn shutdown_result(self, result: io::Result<()>) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().shutdown_results.push(result);
        self
    }

    pub fn shutdown_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<Shutdown>>>,
    ) -> TcpStreamWrapperMock {
        self.shutdown_parameters = parameters.clone();
        self
    }

    pub fn set_read_timeout_result(self, result: io::Result<()>) -> TcpStreamWrapperMock {
        self.results
            .lock()
            .unwrap()
            .set_read_timeout_results
            .push(result);
        self
    }

    pub fn set_read_timeout_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<Option<Duration>>>>,
    ) -> TcpStreamWrapperMock {
        self.set_read_timeout_parameters = parameters.clone();
        self
    }

    pub fn try_clone_result(
        self,
        result: io::Result<Box<dyn TcpStreamWrapper>>,
    ) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().try_clone_results.push(result);
        self
    }

    pub fn peer_addr_result(self, result: io::Result<SocketAddr>) -> TcpStreamWrapperMock {
        self.results.lock().unwrap().peer_addr_result = result;
        self
    }

    pub fn mocked_try_clone(mut self, mock_try_clone: bool) -> TcpStreamWrapperMock {
        self.mocked_try_clone = mock_try_clone;
        self
    }
}
