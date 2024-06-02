// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command::StdStreams;
use core::pin::Pin;
use core::task::Poll;
use itertools::Itertools;
use std::cmp::min;
use std::io;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, Error};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct ByteArrayWriter {
    inner_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

pub struct ByteArrayWriterInner {
    byte_array: Vec<u8>,
    flushed_outputs_opt: Option<Vec<FlushableOutput>>,
    next_error: Option<Error>,
}

impl ByteArrayWriterInner {
    fn new(flush_conscious_mode: bool) -> Self {
        ByteArrayWriterInner {
            byte_array: vec![],
            flushed_outputs_opt: flush_conscious_mode.then_some(vec![]),
            next_error: None,
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        if let Some(flushables) = self.flushed_outputs_opt.as_ref() {
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
        if self.flushed_outputs_opt.is_none() {
            Some(String::from_utf8(self.byte_array.clone()).unwrap())
        } else {
            None
        }
    }

    pub fn get_flushed_strings(&self) -> Option<Vec<String>> {
        todo!()
    }
}

// impl Default for ByteArrayWriterInner {
//     fn default() -> Self {
//         ByteArrayWriterInner {
//             byte_array: vec![],
//             output_separated_by_flushes_opt: None,
//             next_error: None,
//         }
//     }
// }

impl ByteArrayWriter {
    pub fn new(flush_caucious_mode: bool) -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner {
                byte_array: vec![],
                flushed_outputs_opt: flush_caucious_mode.then_some(vec![]),
                next_error: None,
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
    pub fn drain_flushed_strings(&self) -> Option<Vec<String>> {
        let mut arc = self.inner_arc.lock().unwrap();
        let outputs = arc.flushed_outputs_opt.take();
        drain_flushes(outputs)
    }
    pub fn reject_next_write(&mut self, error: Error) {
        self.inner_arc.lock().unwrap().next_error = Some(error);
    }
}

fn drain_flushes(outputs: Option<Vec<FlushableOutput>>) -> Option<Vec<String>> {
    outputs.map(|vec| {
        vec.into_iter()
            .flat_map(|output| {
                if output.already_flushed_opt.is_some() {
                    Some(String::from_utf8(output.byte_array).unwrap())
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
        if let Some(next_error) = inner.next_error.take() {
            Err(next_error)
        } else if let Some(container_with_buffers) = inner.flushed_outputs_opt.as_mut() {
            let mut flushable = if !container_with_buffers.is_empty() {
                let last = container_with_buffers.last().unwrap();
                if last.already_flushed_opt.is_some() {
                    FlushableOutput::default()
                } else {
                    container_with_buffers.remove(0)
                }
            } else {
                FlushableOutput::default()
            };
            for byte in buf {
                flushable.byte_array.push(*byte)
            }
            container_with_buffers.push(flushable);
            Ok(buf.len())
        } else {
            for byte in buf {
                inner.byte_array.push(*byte)
            }
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(container_with_buffers) =
            self.inner_arc.lock().unwrap().flushed_outputs_opt.as_mut()
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
struct FlushableOutput {
    byte_array: Vec<u8>,
    already_flushed_opt: Option<SystemTime>,
}

pub struct FlushedString {
    string: String,
    flushed_at: SystemTime,
}

pub struct FlushedStrings<I>
where
    I: Iterator<Item = FlushedString>,
{
    flushes: I,
}

impl<I> FlushedStrings<I>
where
    I: Iterator<Item = FlushedString>,
{
    // This may be useful if there are doubts about the sequancel of flushed writes collected that
    // are collected during a test from multiple sources as it may be otherwise more convenient
    // in a test to keep distinct writers separate without any hassel with cloning.

    // Above all, this should allow even using standard synchronous Mutexes in the mocks even for
    // async code, as long as we are cereful using the locks only after the testing part itself
    // is over.

    // Not using async Mutexes, if some light rules are sustained, can greatly simplify mantining
    // test utils
    fn next(&mut self) -> Option<(String, SystemTime)> {
        self.flushes
            .next()
            .map(|flushed| (flushed.string, flushed.flushed_at))
    }
}

impl<I> Deref for FlushedStrings<I>
where
    I: Iterator<Item = FlushedString>,
{
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}

#[derive(Clone)]
pub struct AsyncByteArrayWriter {
    inner_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

impl Default for AsyncByteArrayWriter {
    fn default() -> Self {
        todo!()
    }
}

impl AsyncWrite for AsyncByteArrayWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        todo!()
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

pub trait MockedStreamHandleWithStringAssertionMethods {
    fn get_string(&self) -> String;
    fn drain_flushed_strings(&self) -> Option<Vec<String>>;
}

impl AsyncByteArrayWriter {
    pub fn new(flush_conscious_mode: bool) -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner::new(flush_conscious_mode))),
        }
    }
    pub fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.inner_arc.clone()
    }
    pub fn get_bytes(&self) -> Vec<u8> {
        self.inner_arc.lock().unwrap().byte_array.clone()
    }
    pub fn reject_next_write(&mut self, error: Error) {
        self.inner_arc.lock().unwrap().next_error = Some(error);
    }
}

impl MockedStreamHandleWithStringAssertionMethods for AsyncByteArrayWriter {
    fn get_string(&self) -> String {
        String::from_utf8(self.get_bytes()).unwrap()
    }
    fn drain_flushed_strings(&self) -> Option<Vec<String>> {
        todo!("rewrite me to return Option<FlushedStrings>");
        let mut arc = self.inner_arc.lock().unwrap();
        let outputs = arc.flushed_outputs_opt.take();
        drain_flushes(outputs)
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
        todo!()
    }

    pub fn reading_attempted(&self) -> bool {
        todo!()
    }

    pub fn reject_next_write(&mut self, error: Error) {
        todo!()
    }
}

pub struct ByteArrayReaderInner {
    byte_arrays: Vec<Vec<u8>>,
    position: usize,
    next_error: Option<Error>,
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
