// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::peer_actors::BindMessage;
use actix::Recipient;

#[derive(Clone, PartialEq, Debug)]
pub struct BlockchainBridgeConfig {
    pub consuming_private_key: Option<String>,
}

#[derive(Clone)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
}
