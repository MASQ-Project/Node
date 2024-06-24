// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
// use futures::sync::mpsc;
// use futures::sync::mpsc::SendError;
// use futures::sync::mpsc::UnboundedReceiver;
// use futures::sync::mpsc::UnboundedSender;
// use std::net::SocketAddr;
// use futures::channel::mpsc::{SendError, TrySendError, UnboundedReceiver, UnboundedSender};

// #[allow(clippy::result_unit_err)]
// pub trait ReceiverWrapper<T: Send>: Send {
//     fn poll(&mut self) -> Result<Async<Option<T>>, ()>;
// }
//
// pub struct ReceiverWrapperReal<T> {
//     delegate: UnboundedReceiver<T>,
// }
//
// impl<T: Send> ReceiverWrapper<T> for ReceiverWrapperReal<T> {
//     fn poll(&mut self) -> Result<Async<Option<T>>, ()> {
//         self.delegate.poll_next()
//     }
// }
//
// impl<T: Send> ReceiverWrapperReal<T> {
//     pub fn new(delegate: UnboundedReceiver<T>) -> ReceiverWrapperReal<T> {
//         ReceiverWrapperReal { delegate }
//     }
// }
//
// pub trait SenderWrapper<T>: Debug + Send {
//     fn unbounded_send(&self, data: T) -> Result<(), TrySendError<T>>;
//     fn peer_addr(&self) -> SocketAddr;
//     fn clone(&self) -> Box<dyn SenderWrapper<T>>;
// }
//
// #[derive(Debug)]
// pub struct SenderWrapperReal<T> {
//     peer_addr: SocketAddr,
//     delegate: UnboundedSender<T>,
// }
//
// impl<T: 'static + Debug + Send> SenderWrapper<T> for SenderWrapperReal<T> {
//     fn unbounded_send(&self, data: T) -> Result<(), TrySendError<T>> {
//         self.delegate.unbounded_send(data)
//     }
//
//     fn peer_addr(&self) -> SocketAddr {
//         self.peer_addr
//     }
//
//     fn clone(&self) -> Box<dyn SenderWrapper<T>> {
//         Box::new(SenderWrapperReal::new(
//             self.peer_addr(),
//             self.delegate.clone(),
//         ))
//     }
// }
//
// impl<T: Send> SenderWrapperReal<T> {
//     pub fn new(peer_addr: SocketAddr, delegate: UnboundedSender<T>) -> SenderWrapperReal<T> {
//         SenderWrapperReal {
//             peer_addr,
//             delegate,
//         }
//     }
// }
//
// pub trait FuturesChannelFactory<T>: Send {
//     fn make(
//         &mut self,
//         peer_addr: SocketAddr,
//     ) -> (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>);
// }
//
// pub struct FuturesChannelFactoryReal {}
//
// impl<T: 'static + Debug + Send> FuturesChannelFactory<T> for FuturesChannelFactoryReal {
//     fn make(
//         &mut self,
//         peer_addr: SocketAddr,
//     ) -> (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>) {
//         let (tx, rx) = futures::channel::mpsc::unbounded();
//         (
//             Box::new(SenderWrapperReal::new(peer_addr, tx)),
//             Box::new(ReceiverWrapperReal::new(rx)),
//         )
//     }
// }
