// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::fmt::Debug;
use std::net::SocketAddr;
use async_trait::async_trait;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::mpsc::error::{SendError, TryRecvError};

#[async_trait]
pub trait ReceiverWrapper<T: Send>: Send {
    async fn recv(&mut self) -> Option<T>;
    fn try_recv(&mut self) -> Result<T, TryRecvError>;
}

pub struct ReceiverWrapperReal<T> {
    delegate: UnboundedReceiver<T>,
}

#[async_trait]
impl<T: Send> ReceiverWrapper<T> for ReceiverWrapperReal<T> {
    async fn recv(&mut self) -> Option<T> {
        self.delegate.recv().await
    }

    fn try_recv(&mut self) -> Result<T, TryRecvError> {
        self.delegate.try_recv()
    }
}

impl<T: Send> ReceiverWrapperReal<T> {
    pub fn new(delegate: UnboundedReceiver<T>) -> ReceiverWrapperReal<T> {
        Self { delegate }
    }
}

pub trait SenderWrapper<T>: Debug + Send {
    fn send(&self, data: T) -> Result<(), SendError<T>>;
    fn peer_addr(&self) -> SocketAddr;
    fn dup(&self) -> Box<dyn SenderWrapper<T>>;
}

#[derive(Debug)]
pub struct SenderWrapperReal<T> {
    peer_addr: SocketAddr,
    delegate: UnboundedSender<T>,
}

impl<T: 'static + Debug + Send> SenderWrapper<T> for SenderWrapperReal<T> {
    fn send(&self, data: T) -> Result<(), SendError<T>> {
        self.delegate.send(data)
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn dup(&self) -> Box<dyn SenderWrapper<T>> {
        Box::new(SenderWrapperReal::new(
            self.peer_addr(),
            self.delegate.clone(),
        ))
    }
}

impl<T: Send> SenderWrapperReal<T> {
    pub fn new(peer_addr: SocketAddr, delegate: UnboundedSender<T>) -> SenderWrapperReal<T> {
        SenderWrapperReal {
            peer_addr,
            delegate,
        }
    }
}

pub trait FuturesChannelFactory<T>: Send {
    fn make(
        &mut self,
        peer_addr: SocketAddr,
    ) -> (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>);
}

pub struct FuturesChannelFactoryReal {}

impl<T: 'static + Debug + Send> FuturesChannelFactory<T> for FuturesChannelFactoryReal {
    fn make(
        &mut self,
        peer_addr: SocketAddr,
    ) -> (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>) {
        let (tx, rx) = unbounded_channel();
        (
            Box::new(SenderWrapperReal::new(peer_addr, tx)),
            Box::new(ReceiverWrapperReal::new(rx)),
        )
    }
}
