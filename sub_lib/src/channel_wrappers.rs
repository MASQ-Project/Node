// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::fmt::Debug;
use futures::Stream;
use futures::sync::mpsc;
use futures::sync::mpsc::SendError;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::UnboundedSender;
use tokio::prelude::Async;

pub trait ReceiverWrapper<T: Send>: Send {
    fn poll(&mut self) -> Result<Async<Option<T>>, ()>;
}

pub struct ReceiverWrapperReal<T> {
    delegate: UnboundedReceiver<T>
}

impl<T: Send> ReceiverWrapper<T> for ReceiverWrapperReal<T> {
    fn poll(&mut self) -> Result<Async<Option<T>>, ()> {
        self.delegate.poll()
    }
}

impl<T: Send> ReceiverWrapperReal<T> {
    pub fn new(delegate: UnboundedReceiver<T>) -> ReceiverWrapperReal<T> {
        ReceiverWrapperReal { delegate }
    }
}

pub trait SenderWrapper<T>: Debug + Send {
    fn unbounded_send(&mut self, data: T) -> Result<(), SendError<T>>;
    fn clone(&self) -> Box<SenderWrapper<T>>;
}

#[derive(Debug)]
pub struct SenderWrapperReal<T> {
    delegate: UnboundedSender<T>
}

impl<T: 'static + Debug + Send> SenderWrapper<T> for SenderWrapperReal<T> {
    fn unbounded_send(&mut self, data: T) -> Result<(), SendError<T>> {
        self.delegate.unbounded_send(data)
    }
    fn clone(&self) -> Box<SenderWrapper<T>> {
        Box::new(SenderWrapperReal::new(self.delegate.clone()))
    }
}

impl<T: Send> SenderWrapperReal<T> {
    pub fn new(delegate: UnboundedSender<T>) -> SenderWrapperReal<T> {
        SenderWrapperReal { delegate }
    }
}

pub trait FuturesChannelFactory<T> {
    fn make(&mut self) -> (Box<SenderWrapper<T>>, Box<ReceiverWrapper<T>>);
}

pub struct FuturesChannelFactoryReal {}

impl<T: 'static + Debug + Send> FuturesChannelFactory<T> for FuturesChannelFactoryReal {
    fn make(&mut self) -> (Box<SenderWrapper<T>>, Box<ReceiverWrapper<T>>) {
        let (tx, rx) = mpsc::unbounded();
        (Box::new(SenderWrapperReal::new(tx)), Box::new(ReceiverWrapperReal::new(rx)))
    }
}