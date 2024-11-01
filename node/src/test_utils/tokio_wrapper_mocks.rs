// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use std::io;
use std::io::Read;
use std::io::Write;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// TODO: This would probably be more profitable as an enum with three values.
type PollReadResult = (Vec<u8>, Poll<io::Result<()>>);

#[derive(Default)]
pub struct ReadHalfWrapperMock {
    pub poll_read_results: Vec<PollReadResult>,
}

impl ReadHalfWrapper for ReadHalfWrapperMock {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, &mut ReadBuf::new(buf))
    }
}

impl Read for ReadHalfWrapperMock {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl AsyncRead for ReadHalfWrapperMock {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let (data, read_result) = self.get_mut().poll_read_results.remove(0);
        match read_result {
            Poll::Ready(Ok(())) => {
                buf.put_slice(&data);
            },
            _ => {},
        }
        read_result
    }
}

impl ReadHalfWrapperMock {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn poll_read_result(
        mut self,
        data: Vec<u8>,
        result: Poll<io::Result<()>>,
    ) -> ReadHalfWrapperMock {
        self.poll_read_results.push((data, result));
        self
    }

    pub fn poll_read_ok(self, data: Vec<u8>) -> ReadHalfWrapperMock {
        self.poll_read_result(data.clone(), Poll::Ready(Ok(())))
    }

    pub fn poll_read_final(self, data: Vec<u8>) -> ReadHalfWrapperMock {
        self
            .poll_read_result(data.clone(), Poll::Ready(Ok(())))
            .poll_read_result(vec![], Poll::Ready(Ok(())))
    }
}

type ShutdownResults = Vec<Poll<io::Result<()>>>;

#[derive(Default)]
pub struct WriteHalfWrapperMock {
    pub poll_write_params: Arc<Mutex<Vec<Vec<u8>>>>,
    pub poll_write_results: Vec<Poll<io::Result<usize>>>,
    pub poll_close_results: Arc<Mutex<ShutdownResults>>,
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
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_params.lock().unwrap().push(buf.to_vec());
        if self.poll_write_results.is_empty() {
            panic!("WriteHalfWrapperMock: poll_write_results is empty")
        }
        pin!(self).poll_write_results.remove(0)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        unimplemented!("Not needed")
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_close_results.lock().unwrap().is_empty() {
            panic!("WriteHalfWrapperMock: poll_close_results is empty")
        }
        self.poll_close_results.lock().unwrap().remove(0)
    }
}

impl WriteHalfWrapperMock {
    pub fn new() -> WriteHalfWrapperMock {
        WriteHalfWrapperMock {
            poll_write_params: Arc::new(Mutex::new(vec![])),
            poll_write_results: vec![],
            poll_close_results: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn poll_write_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> WriteHalfWrapperMock {
        self.poll_write_params = params_arc.clone();
        self
    }

    pub fn poll_write_result(mut self, result: Poll<io::Result<usize>>) -> WriteHalfWrapperMock {
        self.poll_write_results.push(result);
        self
    }

    pub fn poll_write_ok(self, len: usize) -> WriteHalfWrapperMock {
        self.poll_write_result(Poll::Ready(Ok(len)))
    }

    pub fn poll_close_result(self, result: Poll<io::Result<()>>) -> WriteHalfWrapperMock {
        self.poll_close_results.lock().unwrap().push(result);
        self
    }

    pub fn poll_close_ok(self) -> WriteHalfWrapperMock {
        self.poll_close_result(Poll::Ready(Ok(())))
    }
}
