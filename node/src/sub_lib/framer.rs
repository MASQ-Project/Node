// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[derive(Debug, PartialEq)]
pub struct FramedChunk {
    pub chunk: Vec<u8>,
    pub last_chunk: bool,
}

pub trait Framer: Send {
    fn add_data(&mut self, data: &[u8]);
    fn take_frame(&mut self) -> Option<FramedChunk>;
}
