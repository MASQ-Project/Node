// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use configuration::PortConfiguration;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::net::SocketAddr;
use stream_handler_pool::StreamHandlerPoolSubs;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::neighborhood::NeighborhoodSubs;
use sub_lib::stream_connector::ConnectionInfo;

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
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PoolBindMessage")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::System;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use test_utils::recorder::make_peer_actors;

    #[test]
    fn pool_bind_message_is_debug() {
        let _system = System::new("test");
        let dispatcher_subs = make_peer_actors().dispatcher;
        let stream_handler_pool_subs = make_stream_handler_pool_subs_from(None);
        let neighborhood_subs = make_peer_actors().neighborhood;
        let subject = PoolBindMessage {
            dispatcher_subs,
            stream_handler_pool_subs,
            neighborhood_subs,
        };

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("PoolBindMessage"));
    }
}
