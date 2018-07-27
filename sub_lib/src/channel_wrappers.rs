// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use futures::Stream;
use futures::sync::mpsc;
use futures::sync::mpsc::SendError;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc::UnboundedSender;
use tokio::prelude::Async;
use sequence_buffer::SequencedPacket;

pub trait ReceiverWrapper: Send {
    fn poll(&mut self) -> Result<Async<Option<SequencedPacket>>, ()>;
}

pub struct ReceiverWrapperReal {
    delegate: UnboundedReceiver<SequencedPacket>
}

impl ReceiverWrapper for ReceiverWrapperReal {
    fn poll(&mut self) -> Result<Async<Option<SequencedPacket>>, ()> {
        self.delegate.poll()
    }
}

impl ReceiverWrapperReal {
    pub fn new(delegate: UnboundedReceiver<SequencedPacket>) -> ReceiverWrapperReal {
        ReceiverWrapperReal { delegate }
    }
}

pub trait SenderWrapper: Send {
    fn unbounded_send(&mut self, packet: SequencedPacket) -> Result<(), SendError<SequencedPacket>>;
}

pub struct SenderWrapperReal {
    delegate: UnboundedSender<SequencedPacket>
}

impl SenderWrapper for SenderWrapperReal {
    fn unbounded_send(&mut self, data: SequencedPacket) -> Result<(), SendError<SequencedPacket>> {
        self.delegate.unbounded_send(data)
    }
}

impl SenderWrapperReal {
    pub fn new(delegate: UnboundedSender<SequencedPacket>) -> SenderWrapperReal {
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