// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::peer_actors::BindMessage;
use actix::Recipient;
use actix::Syn;

#[derive(Clone, PartialEq, Debug)]
pub struct BlockchainBridgeConfig {}

#[derive(Clone)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<Syn, BindMessage>,
}
