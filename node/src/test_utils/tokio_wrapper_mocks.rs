// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::cell::RefCell;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use std::io;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::task::{Poll};
use async_trait::async_trait;

#[derive(Default)]
pub struct ReadHalfWrapperMock {
    pub read_results: Vec<io::Result<Vec<u8>>>,
}

#[async_trait]
impl ReadHalfWrapper for ReadHalfWrapperMock {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_results.is_empty() {
            panic!("ReadHalfWrapperMock: read_results is empty")
        }
        let result = self.read_results.remove(0);
        match result {
            Ok(data) => {
                let len = data.len();
                buf[..len].copy_from_slice(&data);
                Ok(len)
            }
            Err(e) => Err(e),
        }
    }
}

impl ReadHalfWrapperMock {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn read_result(
        mut self,
        result: io::Result<Vec<u8>>,
    ) -> ReadHalfWrapperMock {
        self.read_results.push(result);
        self
    }

    pub fn read_ok(self, data: &[u8]) -> ReadHalfWrapperMock {
        self.read_result(Ok(data.to_vec()))
    }

    pub fn read_final(self, data: &[u8]) -> ReadHalfWrapperMock {
        self
            .read_ok(data)
            .read_ok(&[])
    }
}

type ShutdownResults = Vec<Poll<io::Result<()>>>;

#[derive(Default)]
pub struct WriteHalfWrapperMock {
    write_params: Arc<Mutex<Vec<Vec<u8>>>>,
    write_results: RefCell<Vec<io::Result<usize>>>,
    close_results: RefCell<Vec<io::Result<()>>>,
}

#[async_trait]
impl WriteHalfWrapper for WriteHalfWrapperMock {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_params.lock().unwrap().push(buf.to_vec());
        if self.write_results.borrow().is_empty() {
            panic!("WriteHalfWrapperMock: write_results is empty")
        }
        self.write_results.borrow_mut().remove(0)
    }

    async fn flush(&mut self) -> io::Result<()> {
        unimplemented!("Not needed")
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if self.close_results.borrow().is_empty() {
            panic!("WriteHalfWrapperMock: poll_close_results is empty")
        }
        self.close_results.borrow_mut().remove(0)
    }
}

impl Write for WriteHalfWrapperMock {
    fn write(&mut self, _buf: &[u8]) -> Result<usize, io::Error> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        unimplemented!()
    }
}

impl WriteHalfWrapperMock {
    pub fn new() -> WriteHalfWrapperMock {
        WriteHalfWrapperMock {
            write_params: Arc::new(Mutex::new(vec![])),
            write_results: RefCell::new(vec![]),
            close_results: RefCell::new(vec![]),
        }
    }

    pub fn write_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> WriteHalfWrapperMock {
        self.write_params = params_arc.clone();
        self
    }

    pub fn write_result(mut self, result: io::Result<usize>) -> WriteHalfWrapperMock {
        self.write_results.borrow_mut().push(result);
        self
    }

    pub fn write_ok(self, len: usize) -> WriteHalfWrapperMock {
        self.write_result(Ok(len))
    }

    pub fn close_result(self, result: io::Result<()>) -> WriteHalfWrapperMock {
        self.close_results.borrow_mut().push(result);
        self
    }

    pub fn close_ok(self) -> WriteHalfWrapperMock {
        self.close_result(Ok(()))
    }
}
