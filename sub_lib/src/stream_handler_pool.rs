// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::net::SocketAddr;
use actix::ResponseType;
use actix::Subscriber;
use dispatcher::Endpoint;
use peer_actors::BindMessage;
use tcp_wrappers::TcpStreamWrapper;

pub struct AddStreamMsg {
    pub stream: Box<TcpStreamWrapper>
}

impl ResponseType for AddStreamMsg {
    type Item = ();
    type Error = io::Error;
}

#[derive (Debug)]
pub struct RemoveStreamMsg {
    pub socket_addr: SocketAddr
}

impl ResponseType for RemoveStreamMsg {
    type Item = ();
    type Error = io::Error;
}

#[derive (PartialEq, Debug)]
pub struct TransmitDataMsg {
    pub endpoint: Endpoint,
    pub data: Vec<u8>
}

impl ResponseType for TransmitDataMsg {
    type Item = ();
    type Error = io::Error;
}

pub struct StreamHandlerPoolSubs {
    pub add_sub: Box<Subscriber<AddStreamMsg> + Send>,
    pub transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
    pub remove_sub: Box<Subscriber<RemoveStreamMsg> + Send>,
    pub bind: Box<Subscriber<BindMessage> + Send>,
}

impl Clone for StreamHandlerPoolSubs {
    fn clone(&self) -> Self {
        StreamHandlerPoolSubs {
            add_sub: self.add_sub.clone (),
            transmit_sub: self.transmit_sub.clone (),
            remove_sub: self.remove_sub.clone (),
            bind: self.bind.clone(),
        }
    }
}
