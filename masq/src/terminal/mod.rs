// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;

pub mod async_streams;
pub mod terminal_interface_factory;
pub mod non_interactive_terminal_interface;
pub mod interactive_terminal_interface;
mod liso_wrapper;
mod test_utils;

#[derive(Debug)]
pub enum WriteResult {}

#[derive(Debug)]
pub enum ReadResult {
    ConnectionRefused,
}

#[derive(Debug, PartialEq)]
pub enum ReadInput {
    Line(String),
    Quit
}

pub struct TerminalWriter {
    sender: UnboundedSender<String>,
}

impl TerminalWriter {
    pub async fn writeln(&self, str: &str) {
        todo!()
    }

    pub async fn write(&self, str: &str) {
        todo!()
    }
}

pub trait WTermInterface: Send {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>);
    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>);

    fn dup(&self) -> Box<dyn WTermInterface>;
}

#[async_trait]
pub trait RWTermInterface: WTermInterface {
    async fn read_line(&self) -> Result<ReadInput, ReadResult>;

    fn write_only_ref(&self) -> &dyn WTermInterface;

    fn write_only_clone_opt(&self) -> Option<Box<dyn WTermInterface>>;
}


#[async_trait]
pub trait FlushHandle: Drop + Send + Sync {
    // The flush consumes the Arc as an incentive for flushing all the formatted content in one
    // piece (assurance for no interferences with potential other messages waiting to be printed)
    async fn flush(self: Arc<Self>) -> Result<(), WriteResult> {
        // let text = self.concatenate();
        // self.write_internal(text)
        todo!()
    }

    fn concatenate(&self) -> String {
        todo!()
    }

    async fn write_internal(self: Box<Self>, text: String) -> Result<(), WriteResult>;
}