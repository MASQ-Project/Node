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
    captured_writes: Either<Vec<u8>, Vec<FlushableByteOutput>>,
    next_error_opt: Option<std::io::Error>,
}

impl ByteArrayWriterInner {
    fn new(flush_conscious_mode: bool, next_error_opt: Option<std::io::Error>) -> Self {
        let captured_writes = match flush_conscious_mode {
            false => Either::Left(vec![]),
            true => Either::Right(vec![]),
        };
        ByteArrayWriterInner {
            captured_writes,
            next_error_opt,
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        match self.captured_writes.as_ref() {
            Either::Left(bytes) => bytes.clone(),
            Either::Right(flushables) => flushables
                .iter()
                .take_while(|flushable| flushable.already_flushed_opt.is_some())
                .flat_map(|flushable| flushable.byte_array.clone())
                .collect(),
        }
    }

    pub fn get_string(&self) -> Option<String> {
        match self.captured_writes.as_ref() {
            Either::Left(bytes) => Some(String::from_utf8(bytes.clone()).unwrap()),
            _ => None,
        }
    }

    pub fn get_flushed_strings(&self) -> Option<Vec<String>> {
        todo!()
    }
}

impl ByteArrayWriter {
    pub fn new(flush_cautious_mode: bool) -> Self {
        Self {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner::new(
                flush_cautious_mode,
                None,
            ))),
        }
    }
    pub fn inner_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.inner_arc.clone()
    }
    pub fn get_bytes(&self) -> Vec<u8> {
        self.inner_arc
            .lock()
            .unwrap()
            .captured_writes
            .as_ref()
            .left()
            .unwrap()
            .clone()
    }
    pub fn get_string(&self) -> String {
        String::from_utf8(self.get_bytes()).unwrap()
    }
    pub fn drain_flushed_strings(&self) -> FlushedStrings {
        let mut arc = self.inner_arc.lock().unwrap();
        let outputs = arc
            .captured_writes
            .as_mut()
            .right()
            .unwrap()
            .drain(..)
            .collect();
        FlushedStrings::from(drain_flushes(outputs))
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

fn drain_flushes(outputs: Vec<FlushableByteOutput>) -> Vec<FlushedString> {
    outputs
        .into_iter()
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
        .collect()
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
        } else if let Either::Right(container_with_buffers) = inner.captured_writes.as_mut() {
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
            let bytes = inner.captured_writes.as_mut().left().unwrap();
            Self::fill_container(bytes, buf);
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Either::Right(container_with_buffers) =
            self.inner_arc.lock().unwrap().captured_writes.as_mut()
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

#[derive(Default, Clone)]
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
    // This may be useful when there are doubts about the sequence of flushed writes collected that
    // are collected during a test from multiple sources as it may be otherwise more convenient
    // in a test to keep distinct writers separate without any hassle with cloning.

    // Above all, this should allow even using standard synchronous Mutexes in the mocks even for
    // async code, as long as we are careful using the locks only after the act-executing test part
    // is over.

    // Not using async Mutexes, if certain light rules are sustained, can greatly simplify
    // maintenance of our test utils
    fn provide_iterator(&mut self) -> &mut IntoIter<FlushedString> {
        if let Either::Left(vec_opt_mut_ref) = self.flushes.as_mut() {
            let vec_opt = vec_opt_mut_ref.take();
            let iterator = vec_opt.unwrap().into_iter();
            let _ = mem::replace(&mut self.flushes, Either::Right(iterator));
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
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut inner = self.inner_arc.lock().unwrap();
        if let Some(next_error) = inner.next_error_opt.take() {
            Poll::Ready(Err(next_error))
        } else {
            let buf_size = buf.len();
            match inner.captured_writes.as_mut() {
                Either::Right(flushes_container) => {
                    let flushable_output = FlushableByteOutput::new(buf);
                    flushes_container.push(flushable_output)
                }
                Either::Left(byte_array) => byte_array.extend_from_slice(buf),
            }
            Poll::Ready(Ok(buf_size))
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

pub trait StringAssertableStdHandle {
    fn get_string(&self) -> String;
    fn drain_flushed_strings(&self) -> FlushedStrings;
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
    pub fn is_empty(&self) -> bool {
        let lock = self.inner_arc.lock().unwrap();
        match lock.captured_writes.as_ref() {
            Either::Right(flushes) => flushes.is_empty(),
            Either::Left(byte_array) => byte_array.is_empty(),
        }
    }
    pub fn get_bytes(&self) -> Vec<u8> {
        self.inner_arc
            .lock()
            .unwrap()
            .captured_writes
            .as_ref()
            .left()
            .unwrap()
            .clone()
    }
    pub fn reject_next_write(&mut self, error: Error) {
        self.inner_arc.lock().unwrap().next_error_opt = Some(error);
    }
}

impl StringAssertableStdHandle for AsyncByteArrayWriter {
    fn get_string(&self) -> String {
        match self.inner_arc.lock().unwrap().captured_writes.as_ref() {
            Either::Left(bytes) => String::from_utf8(bytes.clone()).unwrap(),
            Either::Right(flushes) => {
                let drained = drain_flushes((*flushes).clone());
                drained.iter().map(|flushed| &flushed.string).join("")
            }
        }
    }
    fn drain_flushed_strings(&self) -> FlushedStrings {
        let mut arc = self.inner_arc.lock().unwrap();
        let outputs = arc
            .captured_writes
            .as_mut()
            .right()
            .unwrap()
            .drain(..)
            .collect();
        FlushedStrings::from(drain_flushes(outputs))
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

    pub fn reject_next_write(&mut self, error: Error) {
        todo!()
    }
}

#[derive(Default)]
pub struct ByteArrayReaderInner {
    byte_arrays: Vec<Vec<u8>>,
    position: usize,
    // TODO is it ever used somewhat well?
    next_error: Option<Error>,
    results_initially: usize,
}

impl HandleToCountReads for ByteArrayReaderInner {
    fn count_reads(&self) -> usize {
        self.results_initially - self.byte_arrays.len()
    }
}

impl ByteArrayReaderInner {
    pub fn new(byte_arrays: Vec<Vec<u8>>) -> Self {
        let results_initially = byte_arrays.len();
        Self {
            byte_arrays,
            position: 0,
            next_error: None,
            results_initially,
        }
    }
}

pub struct StdinReadCounter {
    inner: ReadCounterInner,
}

impl StdinReadCounter {
    pub fn new(stdin_access_point: Arc<Mutex<dyn HandleToCountReads>>) -> Self {
        Self {
            inner: ReadCounterInner::ReadsEnabled { stdin_access_point },
        }
    }

    pub fn reading_not_available() -> Self {
        Self {
            inner: ReadCounterInner::ReadingNotAvailable,
        }
    }

    pub fn reads_opt(&self) -> Option<usize> {
        match &self.inner {
            ReadCounterInner::ReadsEnabled { stdin_access_point } => {
                Some(stdin_access_point.lock().unwrap().count_reads())
            }
            ReadCounterInner::ReadingNotAvailable => None,
        }
    }
}

enum ReadCounterInner {
    ReadsEnabled {
        stdin_access_point: Arc<Mutex<dyn HandleToCountReads>>,
    },
    ReadingNotAvailable,
}

pub trait HandleToCountReads {
    fn count_reads(&self) -> usize;
}

impl From<&AsyncByteArrayReader> for StdinReadCounter {
    fn from(value: &AsyncByteArrayReader) -> Self {
        StdinReadCounter::new(value.byte_array_reader_inner.clone())
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
