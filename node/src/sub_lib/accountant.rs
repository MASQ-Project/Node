// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::banned_dao::BannedDaoFactory;
use crate::accountant::db_access_objects::failed_payable_dao::FailedPayableDaoFactory;
use crate::accountant::db_access_objects::payable_dao::PayableDaoFactory;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayableDaoFactory;
use crate::accountant::db_access_objects::receivable_dao::ReceivableDaoFactory;
use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDaoFactory;
use crate::accountant::scanners::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::{
    checked_conversion, Accountant, ReceivedPayments, ReportTransactionReceipts, ScanError,
    SentPayables,
};
use crate::actor_system_factory::SubsFactory;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::db_config::config_dao::ConfigDaoFactory;
use crate::sub_lib::neighborhood::ConfigChangeMsg;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use actix::{Addr, Message};
use lazy_static::lazy_static;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

lazy_static! {
    pub static ref DEFAULT_EARNING_WALLET: Wallet = Wallet::from_str("0x27d9A2AC83b493f88ce9B4532EDcf74e95B9788d").expect("Internal error");
    // TODO: The consuming wallet should never be defaulted; it should always come in from a
    // (possibly-complicated) command-line parameter, or the bidirectional GUI.
    pub static ref TEMPORARY_CONSUMING_WALLET: Wallet = Wallet::from_str("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").expect("Internal error");
    pub static ref MSG_ID_INCREMENTER: AtomicU32 = AtomicU32::default();
    pub static ref DEFAULT_PAYMENT_THRESHOLDS: PaymentThresholds = PaymentThresholds {
        debt_threshold_gwei: 1_000_000_000,
        maturity_threshold_sec: 1200,
        payment_grace_period_sec: 1200,
        permanent_debt_allowed_gwei: 500_000_000,
        threshold_interval_sec: 21600,
        unban_below_gwei: 500_000_000,
    };
    pub static ref DEFAULT_SCAN_INTERVALS: ScanIntervals = ScanIntervals {
        payable_scan_interval: Duration::from_secs(600),
        pending_payable_scan_interval: Duration::from_secs(60),
        receivable_scan_interval: Duration::from_secs(600)
    };
}

//please, alphabetical order
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct PaymentThresholds {
    pub debt_threshold_gwei: u64,
    pub maturity_threshold_sec: u64,
    pub payment_grace_period_sec: u64,
    pub permanent_debt_allowed_gwei: u64,
    pub threshold_interval_sec: u64,
    pub unban_below_gwei: u64,
}

impl Default for PaymentThresholds {
    fn default() -> Self {
        *DEFAULT_PAYMENT_THRESHOLDS
    }
}

//this code is used in tests in Accountant
impl PaymentThresholds {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - checked_conversion::<u64, i64>(self.maturity_threshold_sec)
            - checked_conversion::<u64, i64>(self.payment_grace_period_sec)
    }
}

pub struct DaoFactories {
    pub payable_dao_factory: Box<dyn PayableDaoFactory>,
    pub sent_payable_dao_factory: Box<dyn SentPayableDaoFactory>,
    pub pending_payable_dao_factory: Box<dyn PendingPayableDaoFactory>, // TODO: This should go away
    pub failed_payable_dao_factory: Box<dyn FailedPayableDaoFactory>,
    pub receivable_dao_factory: Box<dyn ReceivableDaoFactory>,
    pub banned_dao_factory: Box<dyn BannedDaoFactory>,
    pub config_dao_factory: Box<dyn ConfigDaoFactory>,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct ScanIntervals {
    pub payable_scan_interval: Duration,
    pub pending_payable_scan_interval: Duration,
    pub receivable_scan_interval: Duration,
}

impl Default for ScanIntervals {
    fn default() -> Self {
        *DEFAULT_SCAN_INTERVALS
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AccountantSubs {
    pub bind: Recipient<BindMessage>,
    pub config_change_msg_sub: Recipient<ConfigChangeMsg>,
    pub start: Recipient<StartMessage>,
    pub report_routing_service_provided: Recipient<ReportRoutingServiceProvidedMessage>,
    pub report_exit_service_provided: Recipient<ReportExitServiceProvidedMessage>,
    pub report_services_consumed: Recipient<ReportServicesConsumedMessage>,
    pub report_payable_payments_setup: Recipient<BlockchainAgentWithContextMessage>,
    pub report_inbound_payments: Recipient<ReceivedPayments>,
    pub init_pending_payable_fingerprints: Recipient<PendingPayableFingerprintSeeds>,
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

pub struct AccountantSubsFactoryReal {}

impl SubsFactory<Accountant, AccountantSubs> for AccountantSubsFactoryReal {
    fn make(&self, addr: &Addr<Accountant>) -> AccountantSubs {
        Accountant::make_subs_from(addr)
    }
}

// TODO: These four structures all consist of exactly the same five fields. They could be factored out.
#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct ReportRoutingServiceProvidedMessage {
    pub timestamp: SystemTime,
    pub paying_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct ReportExitServiceProvidedMessage {
    pub timestamp: SystemTime,
    pub paying_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct ReportServicesConsumedMessage {
    pub timestamp: SystemTime,
    pub exit: ExitServiceConsumed,
    pub routing_payload_size: usize,
    pub routing: Vec<RoutingServiceConsumed>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoutingServiceConsumed {
    pub earning_wallet: Wallet,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExitServiceConsumed {
    pub earning_wallet: Wallet,
    pub payload_size: usize,
    pub service_rate: u64,
    pub byte_rate: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FinancialStatistics {
    pub total_paid_payable_wei: u128,
    pub total_paid_receivable_wei: u128,
}

#[derive(PartialEq, Eq, Debug)]
pub enum SignConversionError {
    U64(String),
    U128(String),
    I128(String),
}

pub trait MessageIdGenerator {
    fn id(&self) -> u32;
    as_any_ref_in_trait!();
}

#[derive(Default)]
pub struct MessageIdGeneratorReal {}

impl MessageIdGenerator for MessageIdGeneratorReal {
    fn id(&self) -> u32 {
        MSG_ID_INCREMENTER.fetch_add(1, Ordering::Relaxed)
    }
    as_any_ref_in_trait_impl!();
}

#[cfg(test)]
mod tests {
    use crate::accountant::test_utils::AccountantBuilder;
    use crate::accountant::{checked_conversion, Accountant};
    use crate::sub_lib::accountant::{
        AccountantSubsFactoryReal, MessageIdGenerator, MessageIdGeneratorReal, PaymentThresholds,
        ScanIntervals, SubsFactory, DEFAULT_EARNING_WALLET, DEFAULT_PAYMENT_THRESHOLDS,
        DEFAULT_SCAN_INTERVALS, MSG_ID_INCREMENTER, TEMPORARY_CONSUMING_WALLET,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::recorder::{make_accountant_subs_from_recorder, Recorder};
    use actix::Actor;
    use std::str::FromStr;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::Duration;

    static MSG_ID_GENERATOR_TEST_GUARD: Mutex<()> = Mutex::new(());

    impl PaymentThresholds {
        pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
            self.sugg_and_grace(now) - checked_conversion::<u64, i64>(self.threshold_interval_sec)
        }
    }

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
            payable_scan_interval: Duration::from_secs(600),
            pending_payable_scan_interval: Duration::from_secs(60),
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

    #[test]
    fn msg_id_generator_increments_by_one_with_every_call() {
        let _guard = MSG_ID_GENERATOR_TEST_GUARD.lock().unwrap();
        let subject = MessageIdGeneratorReal::default();

        let id1 = subject.id();
        let id2 = subject.id();
        let id3 = subject.id();

        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1)
    }

    #[test]
    fn msg_id_generator_wraps_around_max_value() {
        let _guard = MSG_ID_GENERATOR_TEST_GUARD.lock().unwrap();
        MSG_ID_INCREMENTER.store(u32::MAX, Ordering::Relaxed);
        let subject = MessageIdGeneratorReal::default();
        subject.id(); //this returns the previous, not the newly incremented

        let id = subject.id();

        assert_eq!(id, 0)
    }
}
