// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::io;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::prelude::Async;

pub struct ReadHalfWrapperMock {
    pub poll_read_results: Vec<(Vec<u8>, Result<Async<usize>, io::Error>)>,
}

impl ReadHalfWrapper for ReadHalfWrapperMock {}

impl Read for ReadHalfWrapperMock {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl AsyncRead for ReadHalfWrapperMock {
    fn poll_read(&mut self, buf: &mut [u8]) -> Result<Async<usize>, io::Error> {
        if self.poll_read_results.is_empty() {
            panic!("ReadHalfWrapperMock: poll_read_results is empty")
        }
        let (to_buf, ret_val) = self.poll_read_results.remove(0);
        buf.as_mut().write(to_buf.as_slice()).is_ok();
        ret_val
    }
}

impl ReadHalfWrapperMock {
    pub fn new() -> ReadHalfWrapperMock {
        ReadHalfWrapperMock {
            poll_read_results: vec![],
        }
    }

    pub fn poll_read_result(
        mut self,
        data: Vec<u8>,
        result: Result<Async<usize>, io::Error>,
    ) -> ReadHalfWrapperMock {
        self.poll_read_results.push((data, result));
        self
    }

    pub fn poll_read_ok(self, data: Vec<u8>) -> ReadHalfWrapperMock {
        self.poll_read_result(data.clone(), Ok(Async::Ready(data.len())))
    }
}

pub struct WriteHalfWrapperMock {
    pub poll_write_params: Arc<Mutex<Vec<Vec<u8>>>>,
    pub poll_write_results: Vec<Result<Async<usize>, io::Error>>,
    pub shutdown_results: Arc<Mutex<Vec<Result<Async<()>, io::Error>>>>,
}

impl WriteHalfWrapper for WriteHalfWrapperMock {}

impl Write for WriteHalfWrapperMock {
    fn write(&mut self, _buf: &[u8]) -> Result<usize, io::Error> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        unimplemented!()
    }
}

impl AsyncWrite for WriteHalfWrapperMock {
    fn poll_write(&mut self, buf: &[u8]) -> Result<Async<usize>, io::Error> {
        self.poll_write_params.lock().unwrap().push(buf.to_vec());
        if self.poll_write_results.is_empty() {
            panic!("WriteHalfWrapperMock: poll_write_results is empty")
        }
        self.poll_write_results.remove(0)
    }

    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        if self.shutdown_results.lock().unwrap().is_empty() {
            panic!("WriteHalfWrapperMock: shutdown_results is empty")
        }
        self.shutdown_results.lock().unwrap().remove(0)
    }
}

impl WriteHalfWrapperMock {
    pub fn new() -> WriteHalfWrapperMock {
        WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec![])),
            poll_write_results: vec![],
            shutdown_results: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn poll_write_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> WriteHalfWrapperMock {
        self.poll_write_params = params_arc.clone();
        self
    }

    pub fn poll_write_result(
        mut self,
        result: Result<Async<usize>, io::Error>,
    ) -> WriteHalfWrapperMock {
        self.poll_write_results.push(result);
        self
    }

    pub fn poll_write_ok(self, len: usize) -> WriteHalfWrapperMock {
        self.poll_write_result(Ok(Async::Ready(len)))
    }

    pub fn shutdown_result(self, result: Result<Async<()>, io::Error>) -> WriteHalfWrapperMock {
        self.shutdown_results.lock().unwrap().push(result);
        self
    }

    pub fn shutdown_ok(self) -> WriteHalfWrapperMock {
        self.shutdown_result(Ok(Async::Ready(())))
    }
}
