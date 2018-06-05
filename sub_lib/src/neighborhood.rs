// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use dispatcher::Component;
use node_addr::NodeAddr;
use route::Route;
use cryptde::Key;
use peer_actors::BindMessage;
use actix::Subscriber;

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Box<Subscriber<BindMessage> + Send>,
}
