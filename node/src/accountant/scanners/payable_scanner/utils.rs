// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::comma_joined_stringifiable;
use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureStatus};
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDaoError};
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::db_access_objects::sent_payable_dao::Tx;
use crate::accountant::db_access_objects::utils::{ThresholdUtils, TxHash};
use crate::accountant::db_access_objects::Transaction;
use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
use crate::blockchain::blockchain_interface::data_structures::BatchResults;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::wallet::Wallet;
use bytes::Buf;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::ops::Not;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::{Address, H256};

#[derive(Debug, PartialEq)]
pub struct PayableScanResult {
    pub ui_response_opt: Option<NodeToUiMessage>,
    pub result: NextScanToRun,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NextScanToRun {
    PendingPayableScan,
    NewPayableScan,
    RetryPayableScan,
}

pub fn filter_receiver_addresses_from_txs<'a, T, I>(transactions: I) -> BTreeSet<Address>
where
    T: 'a + Transaction,
    I: Iterator<Item = &'a T>,
{
    transactions.map(|tx| tx.receiver_address()).collect()
}

pub fn generate_status_updates(
    failed_txs: &BTreeSet<FailedTx>,
    status: FailureStatus,
) -> HashMap<TxHash, FailureStatus> {
    failed_txs
        .iter()
        .map(|tx| (tx.hash, status.clone()))
        .collect()
}

pub fn calculate_lengths(batch_results: &BatchResults) -> (usize, usize) {
    (batch_results.sent_txs.len(), batch_results.failed_txs.len())
}

pub fn batch_stats(sent_txs_len: usize, failed_txs_len: usize) -> String {
    format!(
        "Total: {total}, Sent to RPC: {sent_txs_len}, Failed to send: {failed_txs_len}.",
        total = sent_txs_len + failed_txs_len
    )
}

pub fn initial_templates_msg_stats(msg: &InitialTemplatesMessage) -> String {
    let (len, scan_type) = match &msg.initial_templates {
        Either::Left(new_templates) => (new_templates.len(), "new"),
        Either::Right(retry_templates) => (retry_templates.len(), "retry"),
    };

    format!("Found {} {} txs to process", len, scan_type)
}

//debugging purposes only
pub fn investigate_debt_extremes(
    timestamp: SystemTime,
    retrieved_payables: &[PayableAccount],
) -> String {
    #[derive(Clone, Copy, Default)]
    struct PayableInfo {
        balance_wei: u128,
        age: u64,
    }
    fn bigger(payable_1: PayableInfo, payable_2: PayableInfo) -> PayableInfo {
        match payable_1.balance_wei.cmp(&payable_2.balance_wei) {
            Ordering::Greater => payable_1,
            Ordering::Less => payable_2,
            Ordering::Equal => {
                if payable_1.age == payable_2.age {
                    payable_1
                } else {
                    older(payable_1, payable_2)
                }
            }
        }
    }
    fn older(payable_1: PayableInfo, payable_2: PayableInfo) -> PayableInfo {
        match payable_1.age.cmp(&payable_2.age) {
            Ordering::Greater => payable_1,
            Ordering::Less => payable_2,
            Ordering::Equal => {
                if payable_1.balance_wei == payable_2.balance_wei {
                    payable_1
                } else {
                    bigger(payable_1, payable_2)
                }
            }
        }
    }

    if retrieved_payables.is_empty() {
        return "Payable scan found no debts".to_string();
    }
    let (biggest, oldest) = retrieved_payables
        .iter()
        .map(|payable| PayableInfo {
            balance_wei: payable.balance_wei,
            age: timestamp
                .duration_since(payable.last_paid_timestamp)
                .expect("Payable time is corrupt")
                .as_secs(),
        })
        .fold(
            Default::default(),
            |(so_far_biggest, so_far_oldest): (PayableInfo, PayableInfo), payable| {
                (
                    bigger(so_far_biggest, payable),
                    older(so_far_oldest, payable),
                )
            },
        );
    format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                retrieved_payables.len(), biggest.balance_wei, biggest.age,
                oldest.balance_wei, oldest.age)
}

pub fn payables_debug_summary(qualified_accounts: &[(PayableAccount, u128)], logger: &Logger) {
    if qualified_accounts.is_empty() {
        return;
    }
    debug!(logger, "Paying qualified debts:\n{}", {
        let now = SystemTime::now();
        qualified_accounts
            .iter()
            .map(|(payable, threshold_point)| {
                let p_age = now
                    .duration_since(payable.last_paid_timestamp)
                    .expect("Payable time is corrupt");
                format!(
                    "{} wei owed for {} sec exceeds threshold: {} wei; creditor: {}",
                    payable.balance_wei.separate_with_commas(),
                    p_age.as_secs(),
                    threshold_point.separate_with_commas(),
                    payable.wallet
                )
            })
            .join("\n")
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct PendingPayableMetadata<'a> {
    pub recipient: &'a Wallet,
    pub hash: H256,
    pub rowid_opt: Option<u64>,
}

impl<'a> PendingPayableMetadata<'a> {
    pub fn new(
        recipient: &'a Wallet,
        hash: H256,
        rowid_opt: Option<u64>,
    ) -> PendingPayableMetadata<'a> {
        PendingPayableMetadata {
            recipient,
            hash,
            rowid_opt,
        }
    }
}

pub fn mark_pending_payable_fatal_error(
    sent_payments: &[&PendingPayable],
    nonexistent: &[PendingPayableMetadata],
    error: PayableDaoError,
    missing_fingerprints_msg_maker: fn(&[PendingPayableMetadata]) -> String,
    logger: &Logger,
) {
    if !nonexistent.is_empty() {
        error!(logger, "{}", missing_fingerprints_msg_maker(nonexistent))
    };
    panic!(
        "Unable to create a mark in the payable table for wallets {} due to {:?}",
        comma_joined_stringifiable(sent_payments, |pending_p| pending_p
            .recipient_wallet
            .to_string()),
        error
    )
}

pub fn err_msg_for_failure_with_expected_but_missing_fingerprints(
    nonexistent: Vec<H256>,
    serialize_hashes: fn(&[H256]) -> String,
) -> Option<String> {
    nonexistent.is_empty().not().then_some(format!(
        "Ran into failed transactions {} with missing fingerprints. System no longer reliable",
        serialize_hashes(&nonexistent),
    ))
}

pub fn separate_rowids_and_hashes(ids_of_payments: Vec<(u64, H256)>) -> (Vec<u64>, Vec<H256>) {
    ids_of_payments.into_iter().unzip()
}

pub trait PayableThresholdsGauge {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool;
    fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool;
    fn calculate_payout_threshold_in_gwei(
        &self,
        payment_thresholds: &PaymentThresholds,
        x: u64,
    ) -> u128;
    as_any_ref_in_trait!();
}

#[derive(Default)]
pub struct PayableThresholdsGaugeReal {}

impl PayableThresholdsGauge for PayableThresholdsGaugeReal {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
        age <= limit
    }

    fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool {
        balance <= limit
    }

    fn calculate_payout_threshold_in_gwei(
        &self,
        payment_thresholds: &PaymentThresholds,
        debt_age: u64,
    ) -> u128 {
        ThresholdUtils::calculate_finite_debt_limit_by_age(payment_thresholds, debt_age)
    }
    as_any_ref_in_trait_impl!();
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::db_access_objects::receivable_dao::ReceivableAccount;
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::payable_scanner::utils::{
        investigate_debt_extremes, payables_debug_summary, PayableThresholdsGauge,
        PayableThresholdsGaugeReal,
    };
    use crate::accountant::scanners::receivable_scanner::utils::balance_and_age;
    use crate::accountant::{checked_conversion, gwei_to_wei};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use masq_lib::constants::WEIS_IN_GWEI;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::SystemTime;

    #[test]
    fn investigate_debt_extremes_picks_the_most_relevant_records() {
        let now = SystemTime::now();
        let now_t = to_unix_timestamp(now);
        let same_amount_significance = 2_000_000;
        let same_age_significance = from_unix_timestamp(now_t - 30000);
        let payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_unix_timestamp(now_t - 5000),
                pending_payable_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_unix_timestamp(now_t - 10000),
                pending_payable_opt: None,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance_wei: 100,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance_wei: 330,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
        ];

        let result = investigate_debt_extremes(now, payables);

        assert_eq!(result, "Payable scan found 4 debts; the biggest is 2000000 owed for 10000sec, the oldest is 330 owed for 30000sec")
    }

    #[test]
    fn balance_and_age_is_calculated_as_expected() {
        let now = SystemTime::now();
        let offset = 1000;
        let receivable_account = ReceivableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: 10_000_000_000,
            last_received_timestamp: from_unix_timestamp(to_unix_timestamp(now) - offset),
        };

        let (balance, age) = balance_and_age(now, &receivable_account);

        assert_eq!(balance, "10");
        assert_eq!(age.as_secs(), offset as u64);
    }

    #[test]
    fn payables_debug_summary_displays_nothing_for_no_qualified_payments() {
        init_test_logging();
        let logger =
            Logger::new("payables_debug_summary_displays_nothing_for_no_qualified_payments");

        payables_debug_summary(&vec![], &logger);

        TestLogHandler::new().exists_no_log_containing(
            "DEBUG: payables_debug_summary_stays_\
        inert_if_no_qualified_payments: Paying qualified debts:",
        );
    }

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        init_test_logging();
        let now = to_unix_timestamp(SystemTime::now());
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let qualified_payables_and_threshold_points = vec![
            (
                PayableAccount {
                    wallet: make_wallet("wallet0"),
                    balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 2000),
                    last_paid_timestamp: from_unix_timestamp(
                        now - checked_conversion::<u64, i64>(
                            payment_thresholds.maturity_threshold_sec
                                + payment_thresholds.threshold_interval_sec,
                        ),
                    ),
                    pending_payable_opt: None,
                },
                10_000_000_001_152_000_u128,
            ),
            (
                PayableAccount {
                    wallet: make_wallet("wallet1"),
                    balance_wei: gwei_to_wei(payment_thresholds.debt_threshold_gwei - 1),
                    last_paid_timestamp: from_unix_timestamp(
                        now - checked_conversion::<u64, i64>(
                            payment_thresholds.maturity_threshold_sec + 55,
                        ),
                    ),
                    pending_payable_opt: None,
                },
                999_978_993_055_555_580,
            ),
        ];
        let logger = Logger::new("test");

        payables_debug_summary(&qualified_payables_and_threshold_points, &logger);

        TestLogHandler::new().exists_log_containing("Paying qualified debts:\n\
                   10,002,000,000,000,000 wei owed for 2678400 sec exceeds threshold: \
                   10,000,000,001,152,000 wei; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   999,999,999,000,000,000 wei owed for 86455 sec exceeds threshold: \
                   999,978,993,055,555,580 wei; creditor: 0x0000000000000000000000000077616c6c657431");
    }

    #[test]
    fn payout_sloped_segment_in_payment_thresholds_goes_along_proper_line() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 333,
            payment_grace_period_sec: 444,
            permanent_debt_allowed_gwei: 4444,
            debt_threshold_gwei: 8888,
            threshold_interval_sec: 1111111,
            unban_below_gwei: 0,
        };
        let higher_corner_timestamp = payment_thresholds.maturity_threshold_sec;
        let middle_point_timestamp = payment_thresholds.maturity_threshold_sec
            + payment_thresholds.threshold_interval_sec / 2;
        let lower_corner_timestamp =
            payment_thresholds.maturity_threshold_sec + payment_thresholds.threshold_interval_sec;
        let tested_fn = |payment_thresholds: &PaymentThresholds, time| {
            PayableThresholdsGaugeReal {}
                .calculate_payout_threshold_in_gwei(payment_thresholds, time) as i128
        };

        let higher_corner_point = tested_fn(&payment_thresholds, higher_corner_timestamp);
        let middle_point = tested_fn(&payment_thresholds, middle_point_timestamp);
        let lower_corner_point = tested_fn(&payment_thresholds, lower_corner_timestamp);

        let allowed_imprecision = WEIS_IN_GWEI;
        let ideal_template_higher: i128 = gwei_to_wei(payment_thresholds.debt_threshold_gwei);
        let ideal_template_middle: i128 = gwei_to_wei(
            (payment_thresholds.debt_threshold_gwei
                - payment_thresholds.permanent_debt_allowed_gwei)
                / 2
                + payment_thresholds.permanent_debt_allowed_gwei,
        );
        let ideal_template_lower: i128 =
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei);
        assert!(
            higher_corner_point <= ideal_template_higher + allowed_imprecision
                && ideal_template_higher - allowed_imprecision <= higher_corner_point,
            "ideal: {}, real: {}",
            ideal_template_higher,
            higher_corner_point
        );
        assert!(
            middle_point <= ideal_template_middle + allowed_imprecision
                && ideal_template_middle - allowed_imprecision <= middle_point,
            "ideal: {}, real: {}",
            ideal_template_middle,
            middle_point
        );
        assert!(
            lower_corner_point <= ideal_template_lower + allowed_imprecision
                && ideal_template_lower - allowed_imprecision <= lower_corner_point,
            "ideal: {}, real: {}",
            ideal_template_lower,
            lower_corner_point
        )
    }

    #[test]
    fn is_innocent_age_works_for_age_smaller_than_innocent_age() {
        let payable_age = 999;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_age_works_for_age_equal_to_innocent_age() {
        let payable_age = 1000;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_age_works_for_excessive_age() {
        let payable_age = 1001;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, false)
    }

    #[test]
    fn is_innocent_balance_works_for_balance_smaller_than_innocent_balance() {
        let payable_balance = 999;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_balance_works_for_balance_equal_to_innocent_balance() {
        let payable_balance = 1000;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_balance_works_for_excessive_balance() {
        let payable_balance = 1001;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, false)
    }

    #[test]
    fn requires_payments_retry_says_yes() {
        todo!("complete this test with GH-604")
        // let cases = vec![
        //     PendingPayableScanReport {
        //         still_pending: vec![PendingPayableId::new(12, make_tx_hash(456))],
        //         failures: vec![],
        //         confirmed: vec![],
        //     },
        //     PendingPayableScanReport {
        //         still_pending: vec![],
        //         failures: vec![PendingPayableId::new(456, make_tx_hash(1234))],
        //         confirmed: vec![],
        //     },
        //     PendingPayableScanReport {
        //         still_pending: vec![PendingPayableId::new(12, make_tx_hash(456))],
        //         failures: vec![PendingPayableId::new(456, make_tx_hash(1234))],
        //         confirmed: vec![],
        //     },
        //     PendingPayableScanReport {
        //         still_pending: vec![PendingPayableId::new(12, make_tx_hash(456))],
        //         failures: vec![PendingPayableId::new(456, make_tx_hash(1234))],
        //         confirmed: vec![make_pending_payable_fingerprint()],
        //     },
        //     PendingPayableScanReport {
        //         still_pending: vec![PendingPayableId::new(12, make_tx_hash(456))],
        //         failures: vec![],
        //         confirmed: vec![make_pending_payable_fingerprint()],
        //     },
        //     PendingPayableScanReport {
        //         still_pending: vec![],
        //         failures: vec![PendingPayableId::new(456, make_tx_hash(1234))],
        //         confirmed: vec![make_pending_payable_fingerprint()],
        //     },
        // ];
        //
        // cases.into_iter().enumerate().for_each(|(idx, case)| {
        //     let result = case.requires_payments_retry();
        //     assert_eq!(
        //         result, true,
        //         "We expected true, but got false for case of idx {}",
        //         idx
        //     )
        // })
    }

    #[test]
    fn requires_payments_retry_says_no() {
        todo!("complete this test with GH-604")
        // let report = PendingPayableScanReport {
        //     still_pending: vec![],
        //     failures: vec![],
        //     confirmed: vec![make_pending_payable_fingerprint()],
        // };
        //
        // let result = report.requires_payments_retry();
        //
        // assert_eq!(result, false)
    }
}
