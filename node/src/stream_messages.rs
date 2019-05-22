// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::bootstrapper::PortConfiguration;
use crate::stream_handler_pool::StreamHandlerPoolSubs;
use crate::sub_lib::dispatcher::DispatcherSubs;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::stream_connector::ConnectionInfo;
use actix::Message;
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

#[derive(Debug, Message, PartialEq)]
pub struct RemoveStreamMsg {
    pub socket_addr: SocketAddr,
}

#[derive(Message, Clone)]
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
    use crate::node_test_utils::make_stream_handler_pool_subs_from;
    use crate::test_utils::recorder::peer_actors_builder;
    use actix::System;

    #[test]
    fn pool_bind_message_is_debug() {
        let _system = System::new("test");
        let dispatcher_subs = peer_actors_builder().build().dispatcher;
        let stream_handler_pool_subs = make_stream_handler_pool_subs_from(None);
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
