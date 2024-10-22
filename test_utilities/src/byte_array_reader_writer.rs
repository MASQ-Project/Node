// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::cmp::min;
use std::io;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, Error};
use std::sync::{Arc, Mutex};

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

impl Default for ByteArrayWriter {
    fn default() -> Self {
        ByteArrayWriter {
            inner_arc: Arc::new(Mutex::new(ByteArrayWriterInner {
                byte_array: vec![],
                next_error: None,
            })),
        }
    }
}

impl ByteArrayWriter {
    pub fn new() -> ByteArrayWriter {
        Self::default()
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

    pub fn reject_next_write(&mut self, error: Error) {
        self.inner_arc().lock().unwrap().next_error = Some(error);
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
