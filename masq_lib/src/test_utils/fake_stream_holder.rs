// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command::StdStreams;
use std::cmp::min;
use std::io;
use core::pin::Pin;
use core::task::Poll;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, Error};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWrite;

#[derive(Default)]
pub struct ByteArrayWriter {
    inner_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

pub struct ByteArrayWriterInner {
    byte_array: Vec<u8>,
    next_error: Option<Error>,
}

impl ByteArrayWriterInner {
    pub fn get_bytes(&self) -> Vec<u8> {
        self.byte_array.clone()
    }
    pub fn get_string(&self) -> String {
        String::from_utf8(self.get_bytes()).unwrap()
    }
}

impl Default for ByteArrayWriterInner{
    fn default() -> Self {
        ByteArrayWriterInner {
            byte_array: vec![],
            next_error: None,
        }
    }
}

pub trait ByteArrayHelperMethods: Default{
    fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>>;

    fn get_bytes(&self) -> Vec<u8>;
    fn get_string(&self) -> String;

    fn reject_next_write(&mut self, error: Error);
}

impl ByteArrayHelperMethods for ByteArrayWriter{

    fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.inner_arc.clone()
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.inner_arc.lock().unwrap().byte_array.clone()
    }
    fn get_string(&self) -> String {
        String::from_utf8(self.get_bytes()).unwrap()
    }

    fn reject_next_write(&mut self, error: Error) {
        self.inner_arc().lock().unwrap().next_error = Some(error);
    }
}

impl ByteArrayWriter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Write for ByteArrayWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner_arc.lock().unwrap();
        if let Some(next_error) = inner.next_error.take() {
            Err(next_error)
        } else {
            for byte in buf {
                inner.byte_array.push(*byte)
            }
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default, Clone)]
pub struct AsyncByteArrayWriter{
   inner_arc: Arc<tokio::sync::Mutex<ByteArrayWriterInner>>
}

impl AsyncWrite for AsyncByteArrayWriter{
    fn poll_write(self: Pin<&mut Self>, _: &mut std::task::Context<'_>, _: &[u8]) -> Poll<Result<usize, std::io::Error>> { todo!() }
    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Result<(), std::io::Error>> { todo!() }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Result<(), std::io::Error>> { todo!() }
}

impl ByteArrayHelperMethods for AsyncByteArrayWriter{
    fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>>{todo!()}

    fn get_bytes(&self) -> Vec<u8>{todo!()}
    fn get_string(&self) -> String{todo!()}

    fn reject_next_write(&mut self, error: Error){todo!()}
}

impl AsyncByteArrayWriter{
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct ByteArrayReader {
    byte_array: Vec<u8>,
    position: usize,
    next_error: Option<Error>,
}

impl ByteArrayReader {
    pub fn new(byte_array: &[u8]) -> ByteArrayReader {
        ByteArrayReader {
            byte_array: byte_array.to_vec(),
            position: 0,
            next_error: None,
        }
    }

    pub fn reject_next_read(mut self, error: Error) -> ByteArrayReader {
        self.next_error = Some(error);
        self
    }
}

impl Read for ByteArrayReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.next_error.take() {
            Some(error) => Err(error),
            None => {
                let to_copy = min(buf.len(), self.byte_array.len() - self.position);
                #[allow(clippy::needless_range_loop)]
                for idx in 0..to_copy {
                    buf[idx] = self.byte_array[self.position + idx]
                }
                self.position += to_copy;
                Ok(to_copy)
            }
        }
    }
}

impl BufRead for ByteArrayReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self.next_error.take() {
            Some(error) => Err(error),
            None => Ok(&self.byte_array[self.position..]),
        }
    }

    fn consume(&mut self, amt: usize) {
        let result = self.position + amt;
        self.position = if result < self.byte_array.len() {
            result
        } else {
            self.byte_array.len()
        }
    }
}

pub struct FakeStreamHolder {
    pub stdin: ByteArrayReader,
    pub stdout: ByteArrayWriter,
    pub stderr: ByteArrayWriter,
}

impl Default for FakeStreamHolder {
    fn default() -> Self {
        FakeStreamHolder {
            stdin: ByteArrayReader::new(&[0; 0]),
            stdout: ByteArrayWriter::new(),
            stderr: ByteArrayWriter::new(),
        }
    }
}

impl FakeStreamHolder {
    pub fn new() -> FakeStreamHolder {
        Self::default()
    }

    pub fn streams(&mut self) -> StdStreams<'_> {
        StdStreams {
            stdin: &mut self.stdin,
            stdout: &mut self.stdout,
            stderr: &mut self.stderr,
        }
    }
}
