// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::{ReceivedPayments, SentPayments};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::Duration;

lazy_static! {
    pub static ref DEFAULT_EARNING_WALLET: Wallet = Wallet::from_str("0x47fB8671Db83008d382C2e6EA67fA377378c0CeA").expect("Internal error");
    // TODO: The consuming wallet should never be defaulted; it should always come in from a
    // (possibly-complicated) command-line parameter, or the bidirectional GUI.
    pub static ref TEMPORARY_CONSUMING_WALLET: Wallet = Wallet::from_str("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").expect("Internal error");
}

#[derive(Clone, PartialEq, Debug)]
pub struct AccountantConfig {
    pub payable_scan_interval: Duration,
    pub payment_received_scan_interval: Duration,
}

#[derive(Clone)]
pub struct AccountantSubs {
    pub bind: Recipient<BindMessage>,
    pub report_routing_service_provided: Recipient<ReportRoutingServiceProvidedMessage>,
    pub report_exit_service_provided: Recipient<ReportExitServiceProvidedMessage>,
    pub report_routing_service_consumed: Recipient<ReportRoutingServiceConsumedMessage>,
    pub report_exit_service_consumed: Recipient<ReportExitServiceConsumedMessage>,
    pub report_new_payments: Recipient<ReceivedPayments>,
    pub report_sent_payments: Recipient<SentPayments>,
    pub get_financial_statistics_sub: Recipient<GetFinancialStatisticsMessage>,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportRoutingServiceProvidedMessage {
    pub paying_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportExitServiceProvidedMessage {
    pub paying_wallet: Wallet,
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

#[derive(Clone, PartialEq, Debug, Message)]
pub struct GetFinancialStatisticsMessage {
    pub client_id: u64,
}

#[derive(Clone, PartialEq, Debug, Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinancialStatisticsMessage {
    pub pending_credit: i64,
    pub pending_debt: i64,
}
