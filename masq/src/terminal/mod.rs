// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::sync::Arc;
use async_trait::async_trait;
use clap::builder::Str;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub mod async_streams;
pub mod terminal_interface_factory;
pub mod non_interactive_terminal_interface;
pub mod interactive_terminal_interface;
mod liso_wrappers;
mod test_utils;
mod interactive_writing_utils;

#[derive(Debug)]
pub enum WriteResult {}

#[derive(Debug, PartialEq)]
pub enum ReadError {
    ConnectionRefused,
    TerminalOutputInputDisconnected
}

#[derive(Debug, PartialEq)]
pub enum ReadInput {
    Line(String),
    Quit,
    Ignored{msg_opt: Option<String>},
}

pub struct TerminalWriter {
    output_chunks_sender: UnboundedSender<String>,
}

impl TerminalWriter {
    pub fn new(output_chunks_sender: UnboundedSender<String>)->Self{
        Self{
            output_chunks_sender
        }
    }

    pub async fn writeln(&self, str: &str) {
        todo!()
    }

    pub async fn write(&self, str: &str) {
        todo!()
    }
}

pub trait WTermInterfaceImplementingSend: WTermInterface + Send{}

pub trait WTermInterface {
    fn stdout(&self) -> (&TerminalWriter, Box<dyn FlushHandle>);
    fn stderr(&self) -> (&TerminalWriter, Box<dyn FlushHandle>);

    fn dup(&self) -> Box<dyn WTermInterface>;
}

#[async_trait(?Send)]
pub trait RWTermInterface {
    async fn read_line(&mut self) -> Result<ReadInput, ReadError>;

    fn write_only_ref(&self) -> &dyn WTermInterface;

    fn write_only_clone_opt(&self) -> Option<Box<dyn WTermInterface>>;
}


#[async_trait]
#[allow(drop_bounds)]
pub trait FlushHandle: Drop + Send {
    // The flush consumes the Box as a clear incentive for flushing all the formatted content in one
    // piece (assurance for no interferences on other messages waiting to be printed)
    async fn flush(self: Box<Self>) -> Result<(), WriteResult> {
        // let text = self.concatenate();
        // self.write_internal(text)
        todo!()
    }

    fn concatenate(&self) -> String {
        todo!()
    }

    async fn write_internal(self: Box<Self>, text: String) -> Result<(), WriteResult>;
}

