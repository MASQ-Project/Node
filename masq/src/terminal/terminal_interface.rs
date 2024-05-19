// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


use std::io::Stderr;
use async_channel::Sender;
use async_trait::async_trait;
use crossbeam_channel::Receiver;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug)]
pub enum WriteResult{

}

pub enum ReadResult{

}

pub enum ReadInput{
    Line(String)
}

pub struct TerminalWriter{
    sender: UnboundedSender<String>
}

impl TerminalWriter{
    pub async fn writeln(&self, str: &str){
        todo!()
    }

    pub async fn write(&self, str: &str){
        todo!()
    }
}

#[async_trait]
pub trait FlushHandle: Drop + Send{
    async fn flush(&mut self)->Result<(), WriteResult>{
        // let text = self.concatenate();
        // self.write_internal(text)
        todo!()
    }

    fn concatenate(&self) ->String{
        todo!()
    }

    async fn write_internal(&mut self, text: String)-> Result<(), WriteResult>;
}

pub struct NonInteractiveFlushHandle{

}

pub struct InteractiveFlushHandle{

}
















pub trait WTermInterface: Send {
    fn stdout(&self)-> (&TerminalWriter, &dyn FlushHandle);
    fn stderr(&self)->(&TerminalWriter, &dyn FlushHandle);
}

#[async_trait]
pub trait RWTermInterface: WTermInterface {
    async fn read_line(&self) ->Result<ReadInput, ReadResult>;

    fn write_only(&mut self)-> &dyn WTermInterface;
}

pub struct NonInteractiveWTermInterface{

}

impl WTermInterface for NonInteractiveWTermInterface{
    fn stdout(&self) -> (&TerminalWriter, &dyn FlushHandle) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, &dyn FlushHandle) {
        todo!()
    }
}

impl NonInteractiveWTermInterface {
    pub fn new()->Self{
        todo!()
    }
}



pub struct InteractiveRWTermInterface{

}

pub struct InteractiveWTermInterface{

}



impl WTermInterface for InteractiveWTermInterface{
    fn stdout(&self) -> (&TerminalWriter, &dyn FlushHandle) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, &dyn FlushHandle) {
        todo!()
    }
}

#[async_trait]
impl RWTermInterface for InteractiveRWTermInterface{
    async fn read_line(&self) -> Result<ReadInput, ReadResult> {
        todo!()
    }

    fn write_only(&mut self)-> &dyn WTermInterface{
        todo!()
    }
}

impl WTermInterface for InteractiveRWTermInterface{
    fn stdout(&self) -> (&TerminalWriter, &dyn FlushHandle) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, &dyn FlushHandle) {
        todo!()
    }
}

