// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::accountant::ReceivedPayments;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use lazy_static::lazy_static;
use std::time::Duration;

lazy_static! {
    // TODO: This is not a real wallet address. We need a Substratum wallet to accept default payments.
    pub static ref DEFAULT_EARNING_WALLET: Wallet = Wallet::new("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    // TODO: The consuming wallet should never be defaulted; it should always come in from a
    // (possibly-complicated) command-line parameter, or the bidirectional GUI.
    pub static ref TEMPORARY_CONSUMING_WALLET: Wallet = Wallet::new ("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
}

#[derive(Clone, PartialEq, Debug)]
pub struct AccountantConfig {
    pub payable_scan_interval: Duration,
    pub payment_received_scan_interval: Duration,
    pub earning_wallet: Wallet,
}

#[derive(Clone)]
pub struct AccountantSubs {
    pub bind: Recipient<BindMessage>,
    pub report_routing_service_provided: Recipient<ReportRoutingServiceProvidedMessage>,
    pub report_exit_service_provided: Recipient<ReportExitServiceProvidedMessage>,
    pub report_routing_service_consumed: Recipient<ReportRoutingServiceConsumedMessage>,
    pub report_exit_service_consumed: Recipient<ReportExitServiceConsumedMessage>,
    pub report_new_payments: Recipient<ReceivedPayments>,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportRoutingServiceProvidedMessage {
    pub consuming_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportExitServiceProvidedMessage {
    pub consuming_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportRoutingServiceConsumedMessage {
    pub earning_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportExitServiceConsumedMessage {
    pub earning_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}
