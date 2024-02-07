// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::bootstrapper::PortConfiguration;
use crate::stream_handler_pool::StreamHandlerPoolSubs;
use crate::sub_lib::dispatcher::{DispatcherSubs, StreamShutdownMsg};
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::stream_connector::ConnectionInfo;
use actix::{Message, Recipient};
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::net::SocketAddr;

#[derive(Message)]
pub struct AddStreamMsg {
    pub connection_info: ConnectionInfo,
    pub origin_port: Option<u16>,
    pub port_configuration: PortConfiguration,
}

impl AddStreamMsg {
    pub fn new(
        connection_info: ConnectionInfo,
        origin_port: Option<u16>,
        port_configuration: PortConfiguration,
    ) -> AddStreamMsg {
        AddStreamMsg {
            connection_info,
            origin_port,
            port_configuration,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct NonClandestineAttributes {
    pub reception_port: u16,
    pub sequence_number: u64,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum RemovedStreamType {
    Clandestine,
    NonClandestine(NonClandestineAttributes),
}

#[derive(PartialEq, Eq, Message)]
pub struct RemoveStreamMsg {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub stream_type: RemovedStreamType,
    pub dispatcher_sub: Recipient<StreamShutdownMsg>,
}

impl Debug for RemoveStreamMsg {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "RemoveStreamMsg {{ peer_addr: {}, local_addr: {}, stream_type: {:?}, sub: <unprintable> }}",
            self.peer_addr, self.local_addr, self.stream_type
        )
    }
}

#[derive(Message, Clone, PartialEq, Eq)]
pub struct PoolBindMessage {
    pub dispatcher_subs: DispatcherSubs,
    pub stream_handler_pool_subs: StreamHandlerPoolSubs,
    pub neighborhood_subs: NeighborhoodSubs,
}

impl Debug for PoolBindMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PoolBindMessage")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_test_utils::make_stream_handler_pool_subs_from_recorder;
    use crate::test_utils::recorder::{
        make_dispatcher_subs_from_recorder, make_recorder, peer_actors_builder,
    };
    use actix::{Actor, System};

    #[test]
    fn pool_bind_message_is_debug() {
        let _system = System::new("test");
        let (dispatcher, _, _) = make_recorder();
        let dispatcher_subs = make_dispatcher_subs_from_recorder(&dispatcher.start());
        let (stream_handler_pool, _, _) = make_recorder();
        let stream_handler_pool_subs =
            make_stream_handler_pool_subs_from_recorder(&stream_handler_pool.start());
        let neighborhood_subs = peer_actors_builder().build().neighborhood;
        let subject = PoolBindMessage {
            dispatcher_subs,
            stream_handler_pool_subs,
            neighborhood_subs,
        };

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("PoolBindMessage"));
    }
}
