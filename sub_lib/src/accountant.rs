// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use peer_actors::BindMessage;
use wallet::Wallet;

lazy_static! {
    // TODO: This is not a real wallet address. We need a Substratum wallet to accept default payments.
    pub static ref DEFAULT_EARNING_WALLET: Wallet = Wallet::new("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    // TODO: The consuming wallet should never be defaulted; it should always come in from a
    // (possibly-complicated) command-line parameter, or the bidirectional GUI.
    pub static ref TEMPORARY_CONSUMING_WALLET: Wallet = Wallet::new ("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
}

#[derive(Clone, PartialEq, Debug)]
pub struct AccountantConfig {
    pub replace_me: String,
}

#[derive(Clone)]
pub struct AccountantSubs {
    pub bind: Recipient<Syn, BindMessage>,
    pub report_routing_service: Recipient<Syn, ReportRoutingServiceMessage>,
    pub report_exit_service: Recipient<Syn, ReportExitServiceMessage>,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportRoutingServiceMessage {
    pub consuming_wallet: Wallet,
    pub payload_size: u32,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportExitServiceMessage {
    pub consuming_wallet: Wallet,
    pub payload_size: u32,
}
