// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::{
    checked_conversion, Accountant, ReceivedPayments, ReportTransactionReceipts, ScanError,
    SentPayables,
};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use actix::{Addr, Message};
use lazy_static::lazy_static;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

pub const WEIS_OF_GWEI: i128 = 1_000_000_000;

lazy_static! {
    pub static ref DEFAULT_EARNING_WALLET: Wallet = Wallet::from_str("0x27d9A2AC83b493f88ce9B4532EDcf74e95B9788d").expect("Internal error");
    // TODO: The consuming wallet should never be defaulted; it should always come in from a
    // (possibly-complicated) command-line parameter, or the bidirectional GUI.
    pub static ref TEMPORARY_CONSUMING_WALLET: Wallet = Wallet::from_str("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").expect("Internal error");
}

lazy_static! {
    pub static ref DEFAULT_PAYMENT_THRESHOLDS: PaymentThresholds = PaymentThresholds {
        debt_threshold_gwei: 1_000_000_000,
        maturity_threshold_sec: 1200,
        payment_grace_period_sec: 1200,
        permanent_debt_allowed_gwei: 500_000_000,
        threshold_interval_sec: 21600,
        unban_below_gwei: 500_000_000,
    };
}

lazy_static! {
    pub static ref DEFAULT_SCAN_INTERVALS: ScanIntervals = ScanIntervals {
        pending_payable_scan_interval: Duration::from_secs(600),
        payable_scan_interval: Duration::from_secs(600),
        receivable_scan_interval: Duration::from_secs(600)
    };
}

//please, alphabetical order
#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct PaymentThresholds {
    pub debt_threshold_gwei: u64,
    pub maturity_threshold_sec: u64,
    pub payment_grace_period_sec: u64,
    pub permanent_debt_allowed_gwei: u64,
    pub threshold_interval_sec: u64,
    pub unban_below_gwei: u64,
}

impl PaymentThresholds {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - checked_conversion::<u64, i64>(self.maturity_threshold_sec)
            - checked_conversion::<u64, i64>(self.payment_grace_period_sec)
    }

    #[cfg(test)]
    pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
        self.sugg_and_grace(now) - checked_conversion::<u64, i64>(self.threshold_interval_sec)
    }
}

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct ScanIntervals {
    pub pending_payable_scan_interval: Duration,
    pub payable_scan_interval: Duration,
    pub receivable_scan_interval: Duration,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AccountantConfig {
    pub scan_intervals: ScanIntervals,
    pub payment_thresholds: PaymentThresholds,
    pub suppress_initial_scans: bool,
    pub when_pending_too_long_sec: u64,
}

#[derive(Clone, PartialEq)]
pub struct AccountantSubs {
    pub bind: Recipient<BindMessage>,
    pub start: Recipient<StartMessage>,
    pub report_routing_service_provided: Recipient<ReportRoutingServiceProvidedMessage>,
    pub report_exit_service_provided: Recipient<ReportExitServiceProvidedMessage>,
    pub report_routing_service_consumed: Recipient<ReportRoutingServiceConsumedMessage>,
    pub report_exit_service_consumed: Recipient<ReportExitServiceConsumedMessage>,
    pub report_new_payments: Recipient<ReceivedPayments>,
    pub pending_payable_fingerprint: Recipient<PendingPayableFingerprint>,
    pub report_transaction_receipts: Recipient<ReportTransactionReceipts>,
    pub report_sent_payments: Recipient<SentPayables>,
    pub scan_errors: Recipient<ScanError>,
    pub ui_message_sub: Recipient<NodeFromUiMessage>,
}

impl Debug for AccountantSubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "AccountantSubs")
    }
}

pub trait AccountantSubsFactory {
    fn make(&self, addr: &Addr<Accountant>) -> AccountantSubs;
}

pub struct AccountantSubsFactoryReal {}

impl AccountantSubsFactory for AccountantSubsFactoryReal {
    fn make(&self, addr: &Addr<Accountant>) -> AccountantSubs {
        Accountant::make_subs_from(addr)
    }
}

// TODO: These four structures all consist of exactly the same five fields. They could be factored out.
#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportRoutingServiceProvidedMessage {
    pub timestamp: SystemTime,
    pub paying_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportExitServiceProvidedMessage {
    pub timestamp: SystemTime,
    pub paying_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportRoutingServiceConsumedMessage {
    pub timestamp: SystemTime,
    pub earning_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportExitServiceConsumedMessage {
    pub timestamp: SystemTime,
    pub earning_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct FinancialStatistics {
    pub total_paid_payable_wei: u128,
    pub total_paid_receivable_wei: u128,
}

#[derive(PartialEq, Debug)]
pub enum SignConversionError {
    U64(String),
    U128(String),
    I128(String),
}

#[macro_export]
macro_rules! process_individual_range_queries {
    ($self: expr, $msg: expr, $context_id: expr, $($table_name: literal),+) => {
        Ok(match $msg.custom_queries_opt.as_ref(){
            Some(specs) => {
                let (payable_opt, receivable_opt) =

                ($(paste! {
                    if let Some(query_specs) = specs.[<$table_name _opt>].as_ref() {
                        let query = CustomQuery::from(query_specs);
                        Accountant::check_query_is_within_tech_limits(&query, $table_name, $context_id)?;
                        $self.[<request_ $table_name _accounts_by_specific_mode>](
                            query
                        )
                    } else {
                        None
                    }
                }),+);

                Some(
                    QueryResults {
                        payable_opt,
                        receivable_opt,
                    }
                )
            }
            None => None}
        )
    };
}

#[macro_export]
macro_rules! process_top_records_query {
    ($self: expr, $msg: expr, $($table_name: literal),+) => {
        $msg.top_records_opt.map(|config|{
            let (payable, receivable) =

            ($(paste! {
                $self.[<request_ $table_name _accounts_by_specific_mode>](config.into())
               .unwrap_or_default()
            }),+);

            QueryResults{
                payable_opt: Some(payable),
                receivable_opt: Some(receivable)
            }
        })
    };
}

#[cfg(test)]
mod tests {
    use crate::accountant::test_utils::AccountantBuilder;
    use crate::accountant::Accountant;
    use crate::sub_lib::accountant::{
        AccountantSubsFactory, AccountantSubsFactoryReal, PaymentThresholds, ScanIntervals,
        DEFAULT_EARNING_WALLET, DEFAULT_PAYMENT_THRESHOLDS, DEFAULT_SCAN_INTERVALS,
        TEMPORARY_CONSUMING_WALLET,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::recorder::{make_accountant_subs_from_recorder, Recorder};
    use actix::Actor;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn constants_have_correct_values() {
        let default_earning_wallet_expected: Wallet =
            Wallet::from_str("0x27d9A2AC83b493f88ce9B4532EDcf74e95B9788d").expect("Internal error");
        let temporary_consuming_wallet_expected: Wallet =
            Wallet::from_str("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").expect("Internal error");
        let payment_thresholds_expected = PaymentThresholds {
            debt_threshold_gwei: 1_000_000_000,
            maturity_threshold_sec: 1200,
            payment_grace_period_sec: 1200,
            permanent_debt_allowed_gwei: 500_000_000,
            threshold_interval_sec: 21600,
            unban_below_gwei: 500_000_000,
        };
        let scan_intervals_expected = ScanIntervals {
            pending_payable_scan_interval: Duration::from_secs(600),
            payable_scan_interval: Duration::from_secs(600),
            receivable_scan_interval: Duration::from_secs(600),
        };
        assert_eq!(*DEFAULT_SCAN_INTERVALS, scan_intervals_expected);
        assert_eq!(*DEFAULT_PAYMENT_THRESHOLDS, payment_thresholds_expected);
        assert_eq!(*DEFAULT_EARNING_WALLET, default_earning_wallet_expected);
        assert_eq!(
            *TEMPORARY_CONSUMING_WALLET,
            temporary_consuming_wallet_expected
        )
    }

    #[test]
    fn accountant_subs_debug() {
        let addr = Recorder::new().start();

        let subject = make_accountant_subs_from_recorder(&addr);

        assert_eq!(format!("{:?}", subject), "AccountantSubs");
    }

    #[test]
    fn accountant_subs_factory_produces_proper_subs() {
        let subject = AccountantSubsFactoryReal {};
        let accountant = AccountantBuilder::default().build();
        let addr = accountant.start();

        let subs = subject.make(&addr);

        assert_eq!(subs, Accountant::make_subs_from(&addr))
    }
}
