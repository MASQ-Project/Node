// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use peer_actors::BindMessage;

#[derive(Clone, PartialEq, Debug)]
pub struct AccountantConfig {
    pub replace_me: String,
}

#[derive(Clone)]
pub struct AccountantSubs {
    pub bind: Recipient<Syn, BindMessage>,
}
