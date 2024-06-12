// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command::StdStreams;
use core::pin::Pin;
use core::task::Poll;
use itertools::{Either, Itertools};
use std::cell::RefCell;
use std::cmp::min;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, Error};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::vec::IntoIter;
use std::{io, mem};
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct ByteArrayWriter {
    inner_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

pub struct ByteArrayWriterInner {
    byte_array: Vec<u8>,
    flush_separated_writes_opt: Option<Vec<FlushableByteOutput>>,
    next_error_opt: Option<std::io::Error>,
}

impl ByteArrayWriterInner {
    fn new(flush_conscious_mode: bool, next_error_opt: Option<std::io::Error>) -> Self {
        ByteArrayWriterInner {
            byte_array: vec![],
            flush_separated_writes_opt: flush_conscious_mode.then_some(vec![]),
            next_error_opt,
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        if let Some(flushables) = self.flush_separated_writes_opt.as_ref() {
            flushables
                .iter()
                .take_while(|flushable| flushable.already_flushed_opt.is_some())
                .flat_map(|flushable| flushable.byte_array.clone())
                .collect()
        } else {
            self.byte_array.clone()
        }
    }

    pub fn get_string(&self) -> Option<String> {
        if self.flush_separated_writes_opt.is_none() {
            Some(String::from_utf8(self.byte_array.clone()).unwrap())
        } else {
            None
        }
    }

    pub fn get_flushed_strings(&self) -> Option<Vec<String>> {
        todo!()
    }
}

impl ByteArrayWriter {
    pub fn new(flush_caucious_mode: bool) -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner {
                byte_array: vec![],
                flush_separated_writes_opt: flush_caucious_mode.then_some(vec![]),
                next_error_opt: None,
            })),
        }
    }
    pub fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.inner_arc.clone()
    }
    pub fn get_bytes(&self) -> Vec<u8> {
        self.inner_arc.lock().unwrap().byte_array.clone()
    }
    pub fn get_string(&self) -> String {
        String::from_utf8(self.get_bytes()).unwrap()
    }
    pub fn drain_flushed_strings(&self) -> Option<FlushedStrings> {
        let mut arc = self.inner_arc.lock().unwrap();
        let outputs = arc.flush_separated_writes_opt.take();
        drain_flushes(outputs).map(FlushedStrings::from)
    }
    pub fn reject_next_write(&mut self, error: Error) {
        self.inner_arc.lock().unwrap().next_error_opt = Some(error);
    }

    fn fill_container(container: &mut Vec<u8>, bytes: &[u8]) {
        for byte in bytes {
            container.push(*byte)
        }
    }
}

fn drain_flushes(outputs: Option<Vec<FlushableByteOutput>>) -> Option<Vec<FlushedString>> {
    outputs.map(|vec| {
        vec.into_iter()
            .flat_map(|output| {
                if let Some(flush_timestamp) = output.already_flushed_opt {
                    let flushed = FlushedString {
                        string: String::from_utf8(output.byte_array).unwrap(),
                        flushed_at: flush_timestamp,
                    };
                    Some(flushed)
                } else {
                    None
                }
            })
            .collect_vec()
    })
}

impl Default for ByteArrayWriter {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Write for ByteArrayWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner_arc.lock().unwrap();
        if let Some(next_error) = inner.next_error_opt.take() {
            Err(next_error)
        } else if let Some(container_with_buffers) = inner.flush_separated_writes_opt.as_mut() {
            let mut flushable = if let Some(last_flushable_output) = container_with_buffers.last() {
                if last_flushable_output.already_flushed_opt.is_some() {
                    FlushableByteOutput::default()
                } else {
                    container_with_buffers.remove(0)
                }
            } else {
                FlushableByteOutput::default()
            };
            Self::fill_container(&mut flushable.byte_array, buf);
            container_with_buffers.push(flushable);
            Ok(buf.len())
        } else {
            Self::fill_container(&mut inner.byte_array, buf);
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(container_with_buffers) = self
            .inner_arc
            .lock()
            .unwrap()
            .flush_separated_writes_opt
            .as_mut()
        {
            container_with_buffers
                .last_mut()
                .map(|output| output.already_flushed_opt = Some(SystemTime::now()));
        }
        Ok(())
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

// impl BufRead for ByteArrayReader {
//     fn fill_buf(&mut self) -> io::Result<&[u8]> {
//         match self.next_error.take() {
//             Some(error) => Err(error),
//             None => Ok(&self.byte_array[self.position..]),
//         }
//     }
//
//     fn consume(&mut self, amt: usize) {
//         let result = self.position + amt;
//         self.position = if result < self.byte_array.len() {
//             result
//         } else {
//             self.byte_array.len()
//         }
//     }
// }

#[derive(Default)]
struct FlushableByteOutput {
    byte_array: Vec<u8>,
    already_flushed_opt: Option<SystemTime>,
}

impl FlushableByteOutput {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            byte_array: bytes.to_vec(),
            already_flushed_opt: Some(SystemTime::now()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct FlushedString {
    string: String,
    flushed_at: SystemTime,
}

impl FlushedString {
    pub fn new(string: String) -> Self {
        Self {
            string,
            flushed_at: SystemTime::now(),
        }
    }

    pub fn output(&self) -> &str {
        self.string.as_str()
    }

    pub fn timestamp(&self) -> SystemTime {
        self.flushed_at
    }
}

#[derive(Debug)]
pub struct FlushedStrings {
    flushes: Either<Option<Vec<FlushedString>>, IntoIter<FlushedString>>,
}

impl FlushedStrings {
    // This may be useful when there are doubts about the sequance of flushed writes collected that
    // are collected during a test from multiple sources as it may be otherwise more convenient
    // in a test to keep distinct writers separate without any hassel with cloning.

    // Above all, this should allow even using standard synchronous Mutexes in the mocks even for
    // async code, as long as we are cereful using the locks only after the testing part itself
    // is over.

    // Not using async Mutexes, if some light rules are sustained, can greatly simplify mantining
    // test utils
    fn provide_iterator(&mut self) -> &mut IntoIter<FlushedString> {
        if let Either::Left(vec_opt_mut_ref) = self.flushes.as_mut() {
            let vec_opt = vec_opt_mut_ref.take();
            let iterator = vec_opt.unwrap().into_iter();
            mem::replace(&mut self.flushes, Either::Right(iterator));
        }

        self.flushes.as_mut().right().unwrap()
    }

    pub fn next_flush(&mut self) -> Option<FlushedString> {
        self.provide_iterator().next()
    }

    pub fn as_simple_strings(&mut self) -> Vec<String> {
        self.provide_iterator()
            .map(|flushed_str| flushed_str.string)
            .collect()
    }
}

impl From<Vec<FlushedString>> for FlushedStrings {
    fn from(flushes: Vec<FlushedString>) -> Self {
        Self {
            flushes: Either::Left(Some(flushes)),
        }
    }
}

#[derive(Clone)]
pub struct AsyncByteArrayWriter {
    inner_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

impl Default for AsyncByteArrayWriter {
    fn default() -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner::new(false, None))),
        }
    }
}

impl AsyncWrite for AsyncByteArrayWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut inner = self.inner_arc.lock().unwrap();
        if let Some(next_error) = inner.next_error_opt.take() {
            Poll::Ready(Err(next_error))
        } else {
            let buf_size = buf.len();
            if let Some(vec) = inner.flush_separated_writes_opt.as_mut() {
                let flushable_output = FlushableByteOutput::new(buf);
                vec.push(flushable_output)
            } else {
                inner.byte_array.extend_from_slice(buf);
            }
            Poll::Ready(Ok(buf_size))
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

pub trait StringAssertionMethods {
    fn get_string(&self) -> String;
    fn drain_flushed_strings(&self) -> Option<FlushedStrings>;
}

impl AsyncByteArrayWriter {
    pub fn new(flush_conscious_mode: bool, error_opt: Option<std::io::Error>) -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner::new(
                flush_conscious_mode,
                error_opt,
            ))),
        }
    }
    pub fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.inner_arc.clone()
    }
    pub fn get_bytes(&self) -> Vec<u8> {
        self.inner_arc.lock().unwrap().byte_array.clone()
    }
    pub fn reject_next_write(&mut self, error: Error) {
        self.inner_arc.lock().unwrap().next_error_opt = Some(error);
    }
}

impl StringAssertionMethods for AsyncByteArrayWriter {
    fn get_string(&self) -> String {
        String::from_utf8(self.get_bytes()).unwrap()
    }
    fn drain_flushed_strings(&self) -> Option<FlushedStrings> {
        let mut arc = self.inner_arc.lock().unwrap();
        let outputs = arc.flush_separated_writes_opt.take();
        drain_flushes(outputs).map(FlushedStrings::from)
    }
}

#[derive(Clone)]
pub struct AsyncByteArrayReader {
    byte_array_reader_inner: Arc<Mutex<ByteArrayReaderInner>>,
}

impl AsyncRead for AsyncByteArrayReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

impl AsyncByteArrayReader {
    pub fn new(read_inputs: Vec<Vec<u8>>) -> Self {
        Self {
            byte_array_reader_inner: Arc::new(Mutex::new(ByteArrayReaderInner::new(read_inputs))),
        }
    }

    pub fn reading_attempted(&self) -> bool {
        todo!()
    }

    pub fn reject_next_write(&mut self, error: Error) {
        todo!()
    }
}

#[derive(Default)]
pub struct ByteArrayReaderInner {
    byte_arrays: Vec<Vec<u8>>,
    position: usize,
    next_error: Option<Error>,
}

impl ByteArrayReaderInner {
    pub fn new(read_inputs: Vec<Vec<u8>>) -> Self {
        Self {
            byte_arrays: read_inputs,
            ..Default::default()
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
            stdout: ByteArrayWriter::default(),
            stderr: ByteArrayWriter::default(),
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
