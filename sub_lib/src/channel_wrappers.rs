use futures::Stream;
use futures::sync::mpsc;
use futures::sync::mpsc::SendError;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::UnboundedSender;
use tokio::prelude::Async;

pub trait ReceiverWrapper: Send {
    fn poll(&mut self) -> Result<Async<Option<Vec<u8>>>, ()>;
}

pub struct ReceiverWrapperReal {
    delegate: UnboundedReceiver<Vec<u8>>
}

impl ReceiverWrapper for ReceiverWrapperReal {
    fn poll(&mut self) -> Result<Async<Option<Vec<u8>>>, ()> {
        self.delegate.poll()
    }
}

impl ReceiverWrapperReal {
    pub fn new(delegate: UnboundedReceiver<Vec<u8>>) -> ReceiverWrapperReal {
        ReceiverWrapperReal { delegate }
    }
}

pub trait SenderWrapper: Send {
    fn unbounded_send(&mut self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>>;
}

pub struct SenderWrapperReal {
    delegate: UnboundedSender<Vec<u8>>
}

impl SenderWrapper for SenderWrapperReal {
    fn unbounded_send(&mut self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        self.delegate.unbounded_send(data)
    }
}

impl SenderWrapperReal {
    pub fn new(delegate: UnboundedSender<Vec<u8>>) -> SenderWrapperReal {
        SenderWrapperReal { delegate }
    }
}

pub trait FuturesChannelFactory {
    fn make(&mut self) -> (Box<SenderWrapper>, Box<ReceiverWrapper>);
}

pub struct FuturesChannelFactoryReal {}

impl FuturesChannelFactory for FuturesChannelFactoryReal {
    fn make(&mut self) -> (Box<SenderWrapper>, Box<ReceiverWrapper>) {
        let (tx, rx) = mpsc::unbounded();
        (Box::new(SenderWrapperReal::new(tx)), Box::new(ReceiverWrapperReal::new(rx)))
    }
}