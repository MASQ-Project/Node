use crate::sub_lib::channel_wrappers::FuturesChannelFactory;
use crate::sub_lib::channel_wrappers::ReceiverWrapper;
use crate::sub_lib::channel_wrappers::SenderWrapper;
use std::cell::RefCell;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use tokio::sync::mpsc::error::{SendError, TryRecvError};

type FuturesChannelFactoryMockResult<T> = (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>);

#[derive(Default)]
pub struct FuturesChannelFactoryMock<T> {
    make_results: Vec<FuturesChannelFactoryMockResult<T>>,
}

impl<T: 'static + Clone + Debug + Send> FuturesChannelFactory<T> for FuturesChannelFactoryMock<T> {
    fn make(
        &mut self,
        peer_addr: SocketAddr,
    ) -> (Box<dyn SenderWrapper<T>>, Box<dyn ReceiverWrapper<T>>) {
        if self.make_results.is_empty() {
            (
                Box::new(SenderWrapperMock::new(peer_addr)),
                Box::new(ReceiverWrapperMock::new()),
            )
        } else {
            self.make_results.remove(0)
        }
    }
}

impl<T: 'static + Clone + Debug + Send> FuturesChannelFactoryMock<T> {
    pub fn new() -> Self {
        Self { make_results: vec![] }
    }

    pub fn make_result(mut self, sender: SenderWrapperMock<T>, receiver: ReceiverWrapperMock<T>) -> Self {
        self.make_results.push((Box::new(sender), Box::new(receiver)));
        self
    }
}

#[derive(Default)]
pub struct ReceiverWrapperMock<T> {
    recv_results: RefCell<Vec<Option<T>>>,
    try_recv_results: RefCell<Vec<Result<T, TryRecvError>>>,
}

#[async_trait]
impl<T: Send> ReceiverWrapper<T> for ReceiverWrapperMock<T> {
    async fn recv(&mut self) -> Option<T> {
        self.recv_results.borrow_mut().remove(0)
    }
    fn try_recv(&mut self) -> Result<T, TryRecvError> {
        self.try_recv_results.borrow_mut().remove(0)
    }
}

impl<T> ReceiverWrapperMock<T> {
    pub fn new() -> Self {
        Self {
            recv_results: RefCell::new(vec![]),
            try_recv_results: RefCell::new(vec![]),
        }
    }

    pub fn recv_result(mut self, result: Option<T>) -> Self {
        self.recv_results.borrow_mut().push(result);
        self
    }

    pub fn try_recv_result(mut self, result: Result<T, TryRecvError>) -> Self {
        self.try_recv_results.borrow_mut().push(result);
        self
    }
}

#[derive(Debug)]
pub struct SenderWrapperMock<T> {
    peer_addr_result: SocketAddr,
    unbounded_send_params: Arc<Mutex<Vec<T>>>,
    unbounded_send_results: RefCell<Vec<Result<(), SendError<T>>>>,
}

impl<T: 'static + Clone + Debug + Send> SenderWrapper<T> for SenderWrapperMock<T> {
    fn send(&self, data: T) -> Result<(), SendError<T>> {
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

    fn dup(&self) -> Box<dyn SenderWrapper<T>> {
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
