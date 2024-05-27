// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use async_channel::Sender;
use async_trait::async_trait;
use crossbeam_channel::Receiver;
use std::io::Stderr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug)]
pub enum WriteResult {}

pub enum ReadResult {
    ConnectionRefused,
}

pub enum ReadInput {
    Line(String),
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

#[async_trait]
pub trait FlushHandle: Drop + Send + Sync {
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

pub struct NonInteractiveFlushHandle {}

pub struct InteractiveFlushHandle {}

pub trait WTermInterface: Send {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>);
    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>);

    fn dup(&self) -> Box<dyn WTermInterface>;
}

#[async_trait]
pub trait RWTermInterface: WTermInterface {
    async fn read_line(&self) -> Result<ReadInput, ReadResult>;

    fn write_only_ref(&mut self) -> &dyn WTermInterface;

    fn write_only_clone_opt(&mut self) -> Option<Box<dyn WTermInterface>>;
}

pub struct NonInteractiveWTermInterface {}

impl WTermInterface for NonInteractiveWTermInterface {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn dup(&self) -> Box<dyn WTermInterface> {
        todo!()
    }
}

impl NonInteractiveWTermInterface {
    pub fn new() -> Self {
        todo!()
    }
}

pub struct InteractiveRWTermInterface {}

pub struct InteractiveWTermInterface {}

impl WTermInterface for InteractiveWTermInterface {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn dup(&self) -> Box<dyn WTermInterface> {
        todo!()
    }
}

#[async_trait]
impl RWTermInterface for InteractiveRWTermInterface {
    async fn read_line(&self) -> Result<ReadInput, ReadResult> {
        todo!()
    }

    fn write_only_ref(&mut self) -> &dyn WTermInterface {
        todo!()
    }

    fn write_only_clone_opt(&mut self) -> Option<Box<dyn WTermInterface>> {
        todo!()
    }
}

impl WTermInterface for InteractiveRWTermInterface {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn dup(&self) -> Box<dyn WTermInterface> {
        todo!()
    }
}
