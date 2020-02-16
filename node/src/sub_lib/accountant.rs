// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::{ReceivedPayments, SentPayments};
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use lazy_static::lazy_static;
use masq_lib::ui_gateway::NodeFromUiMessage;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
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
    pub start: Recipient<StartMessage>,
    pub report_routing_service_provided: Recipient<ReportRoutingServiceProvidedMessage>,
    pub report_exit_service_provided: Recipient<ReportExitServiceProvidedMessage>,
    pub report_routing_service_consumed: Recipient<ReportRoutingServiceConsumedMessage>,
    pub report_exit_service_consumed: Recipient<ReportExitServiceConsumedMessage>,
    pub report_new_payments: Recipient<ReceivedPayments>,
    pub report_sent_payments: Recipient<SentPayments>,
    pub get_financial_statistics_sub: Recipient<GetFinancialStatisticsMessage>,
    pub ui_message_sub: Recipient<NodeFromUiMessage>,
}

impl Debug for AccountantSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "AccountantSubs")
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn accountant_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = AccountantSubs {
            bind: recipient!(recorder, BindMessage),
            start: recipient!(recorder, StartMessage),
            report_routing_service_provided: recipient!(
                recorder,
                ReportRoutingServiceProvidedMessage
            ),
            report_exit_service_provided: recipient!(recorder, ReportExitServiceProvidedMessage),
            report_routing_service_consumed: recipient!(
                recorder,
                ReportRoutingServiceConsumedMessage
            ),
            report_exit_service_consumed: recipient!(recorder, ReportExitServiceConsumedMessage),
            report_new_payments: recipient!(recorder, ReceivedPayments),
            report_sent_payments: recipient!(recorder, SentPayments),
            get_financial_statistics_sub: recipient!(recorder, GetFinancialStatisticsMessage),
            ui_message_sub: recipient!(recorder, NodeFromUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "AccountantSubs");
    }
}
