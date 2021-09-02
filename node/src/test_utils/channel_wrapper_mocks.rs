use crate::sub_lib::channel_wrappers::FuturesChannelFactory;
use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::channel_wrappers::SenderWrapper;
use futures::sync::mpsc::SendError;
use std::cell::RefCell;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::prelude::Async;

type FuturesChannelFactoryMockResult<T> = (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>);

#[derive(Default)]
pub struct FuturesChannelFactoryMock<T> {
    pub results: Vec<FuturesChannelFactoryMockResult<T>>,
}

impl<T: 'static + Clone + Debug + Send> FuturesChannelFactory<T> for FuturesChannelFactoryMock<T> {
    fn make(
        &mut self,
        peer_addr: SocketAddr,
    ) -> (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>) {
        if self.results.is_empty() {
            (
                Box::new(SenderWrapperMock::new(peer_addr)),
                Box::new(ReceiverWrapperMock::new()),
            )
        } else {
            self.results.remove(0)
        }
    }
}

#[derive(Default)]
pub struct ReceiverWrapperMock<T> {
    pub poll_results: Vec<Result<Async<Option<T>>, ()>>,
}

impl<T: Send> ReceiverWrapper<T> for ReceiverWrapperMock<T> {
    fn poll(&mut self) -> Result<Async<Option<T>>, ()> {
        if !self.poll_results.is_empty() {
            self.poll_results.remove(0)
        } else {
            panic!("ReceiverWrapper tried to remove from pull_results but there were none");
        }
    }
}

impl<T> ReceiverWrapperMock<T> {
    pub fn new() -> Self {
        Self {
            poll_results: vec![],
        }
    }
}

#[derive(Debug)]
pub struct SenderWrapperMock<T> {
    peer_addr_result: SocketAddr,
    unbounded_send_params: Arc<Mutex<Vec<T>>>,
    unbounded_send_results: RefCell<Vec<Result<(), SendError<T>>>>,
}

impl<T: 'static + Clone + Debug + Send> SenderWrapper<T> for SenderWrapperMock<T> {
    fn unbounded_send(&self, data: T) -> Result<(), SendError<T>> {
        self.unbounded_send_params.lock().unwrap().push(data);
        if self.unbounded_send_results.borrow().is_empty() {
            Ok(())
        } else {
            self.unbounded_send_results.borrow_mut().remove(0)
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr_result
    }

    fn clone(&self) -> Box<dyn SenderWrapper<T>> {
        Box::new(SenderWrapperMock {
            peer_addr_result: self.peer_addr_result,
            unbounded_send_params: self.unbounded_send_params.clone(),
            unbounded_send_results: self.unbounded_send_results.clone(),
        })
    }
}

impl<T> SenderWrapperMock<T> {
    pub fn new(peer_addr: SocketAddr) -> SenderWrapperMock<T> {
        SenderWrapperMock {
            peer_addr_result: peer_addr,
            unbounded_send_params: Arc::new(Mutex::new(vec![])),
            unbounded_send_results: RefCell::new(vec![]),
        }
    }

    pub fn unbounded_send_params(mut self, params: &Arc<Mutex<Vec<T>>>) -> SenderWrapperMock<T> {
        self.unbounded_send_params = params.clone();
        self
    }

    pub fn unbounded_send_result(self, result: Result<(), SendError<T>>) -> SenderWrapperMock<T> {
        self.unbounded_send_results.borrow_mut().push(result);
        self
    }
}
