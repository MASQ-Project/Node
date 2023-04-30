// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_scanner_utils {
    use crate::accountant::dao_utils::ThresholdUtils;
    use crate::accountant::payable_dao::{Payable, PayableAccount};
    use crate::accountant::SentPayables;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::sub_lib::accountant::PaymentThresholds;
    use itertools::Itertools;
    use masq_lib::logger::Logger;
    use masq_lib::utils::plus;
    #[cfg(test)]
    use std::any::Any;
    use std::cmp::Ordering;
    use std::time::SystemTime;
    use thousands::Separable;

    //debugging purposes only
    pub fn investigate_debt_extremes(
        timestamp: SystemTime,
        all_non_pending_payables: &[PayableAccount],
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

        if all_non_pending_payables.is_empty() {
            return "Payable scan found no debts".to_string();
        }

        let (biggest, oldest) = all_non_pending_payables
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
                all_non_pending_payables.len(), biggest.balance_wei, biggest.age,
                oldest.balance_wei, oldest.age)
    }

    pub fn separate_errors(
        sent_payments: &SentPayables,
        logger: &Logger,
    ) -> (Vec<Payable>, Vec<BlockchainError>) {
        sent_payments
            .payable
            .iter()
            .fold((vec![], vec![]), |so_far, payment| {
                match payment {
                    Ok(payment_sent) => (plus(so_far.0, payment_sent.clone()), so_far.1),
                    Err(error) => {

                        logger.warning(|| match &error {
                            BlockchainError::TransactionFailed { .. } => format!("Encountered transaction error at this end: '{:?}'", error),
                            x => format!("Outbound transaction failure due to '{:?}'. Please check your blockchain service URL configuration.", x)
                        });

                        (so_far.0, plus(so_far.1, error.clone()))
                    }
                }
            })
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

    pub trait PayableThresholdsGauge {
        fn is_innocent_age(&self, age: u64, limit: u64) -> bool;
        fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool;
        fn calculate_payout_threshold_in_gwei(
            &self,
            payment_thresholds: &PaymentThresholds,
            x: u64,
        ) -> u128;
        declare_as_any!();
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
        implement_as_any!();
    }
}

pub mod pending_payable_scanner_utils {
    use crate::accountant::{PendingPayableId, PendingTransactionStatus};
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use masq_lib::logger::Logger;
    use masq_lib::utils::ExpectValue;
    use std::time::SystemTime;

    pub fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
        timestamp
            .elapsed()
            .expect("time calculation for elapsed failed")
            .as_millis()
    }

    pub fn handle_none_status(
        fingerprint: &PendingPayableFingerprint,
        max_pending_interval: u64,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        info!(
            logger,
            "Pending transaction '{:?}' couldn't be confirmed at attempt \
            {} at {}ms after its sending",
            fingerprint.hash,
            fingerprint.attempt_opt.expectv("initialized attempt"),
            elapsed_in_ms(fingerprint.timestamp)
        );
        let elapsed = fingerprint
            .timestamp
            .elapsed()
            .expect("we should be older now");
        let transaction_id = PendingPayableId {
            hash: fingerprint.hash,
            rowid: fingerprint.rowid_opt.expectv("initialized rowid"),
        };
        if max_pending_interval <= elapsed.as_secs() {
            error!(
                logger,
                "Pending transaction '{}' has exceeded the maximum pending time \
                ({}sec) and the confirmation process is going to be aborted now \
                at the final attempt {}; manual resolution is required from the \
                user to complete the transaction.",
                fingerprint.hash,
                max_pending_interval,
                fingerprint.attempt_opt.expectv("initialized attempt")
            );
            PendingTransactionStatus::Failure(transaction_id)
        } else {
            PendingTransactionStatus::StillPending(transaction_id)
        }
    }

    pub fn handle_status_with_success(
        fingerprint: &PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        info!(
            logger,
            "Transaction '{:?}' has been added to the blockchain; detected locally at attempt \
            {} at {}ms after its sending",
            fingerprint.hash,
            fingerprint.attempt_opt.expectv("initialized attempt"),
            elapsed_in_ms(fingerprint.timestamp)
        );
        PendingTransactionStatus::Confirmed(fingerprint.clone())
    }

    pub fn handle_status_with_failure(
        fingerprint: &PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        error!(
            logger,
            "Pending transaction '{}' announced as a failure, interpreting attempt \
            {} after {}ms from the sending",
            fingerprint.hash,
            fingerprint.attempt_opt.expectv("initialized attempt"),
            elapsed_in_ms(fingerprint.timestamp)
        );
        PendingTransactionStatus::Failure(fingerprint.into())
    }
}

pub mod receivable_scanner_utils {
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::wei_to_gwei;
    use std::time::{Duration, SystemTime};
    use thousands::Separable;

    pub fn balance_and_age(time: SystemTime, account: &ReceivableAccount) -> (String, Duration) {
        let balance = wei_to_gwei::<i64, i128>(account.balance_wei).separate_with_commas();
        let age = time
            .duration_since(account.last_received_timestamp)
            .unwrap_or_else(|_| Duration::new(0, 0));
        (balance, age)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::dao_utils::{from_time_t, to_time_t};
    use crate::accountant::payable_dao::{Payable, PayableAccount};
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::scanners_utils::payable_scanner_utils::{
        investigate_debt_extremes, payables_debug_summary, separate_errors, PayableThresholdsGauge,
        PayableThresholdsGaugeReal,
    };
    use crate::accountant::scanners_utils::receivable_scanner_utils::balance_and_age;
    use crate::accountant::{checked_conversion, gwei_to_wei, SentPayables};
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use masq_lib::constants::WEIS_IN_GWEI;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::SystemTime;

    #[test]
    fn investigate_debt_extremes_picks_the_most_relevant_records() {
        let now = SystemTime::now();
        let now_t = to_time_t(now);
        let same_amount_significance = 2_000_000;
        let same_age_significance = from_time_t(now_t - 30000);
        let payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_time_t(now_t - 5000),
                pending_payable_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_time_t(now_t - 10000),
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
            last_received_timestamp: from_time_t(to_time_t(now) - offset),
        };

        let (balance, age) = balance_and_age(now, &receivable_account);

        assert_eq!(balance, "10");
        assert_eq!(age.as_secs(), offset as u64);
    }

    #[test]
    fn separate_errors_works() {
        init_test_logging();
        let test_name = "separate_errors_works";
        let payable_ok = Payable {
            to: make_wallet("blah"),
            amount: 5555,
            timestamp: SystemTime::now(),
            tx_hash: Default::default(),
        };
        let error = BlockchainError::SignedValueConversion(666);
        let sent_payable = SentPayables {
            timestamp: SystemTime::now(),
            payable: vec![Ok(payable_ok.clone()), Err(error.clone())],
            response_skeleton_opt: None,
        };

        let (ok, err) = separate_errors(&sent_payable, &Logger::new(test_name));

        assert_eq!(ok, vec![payable_ok]);
        assert_eq!(err, vec![error.clone()]);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {}: Outbound transaction failure due to '{:?}",
            test_name, error
        ));
    }

    #[test]
    fn payables_debug_summary_stays_inert_if_no_qualified_payments() {
        init_test_logging();
        let logger = Logger::new("payables_debug_summary_stays_inert_if_no_qualified_payments");

        payables_debug_summary(&vec![], &logger);

        TestLogHandler::new().exists_no_log_containing(
            "DEBUG: payables_debug_summary_stays_\
        inert_if_no_qualified_payments: Paying qualified debts:",
        );
    }

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        init_test_logging();
        let now = to_time_t(SystemTime::now());
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
                    last_paid_timestamp: from_time_t(
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
                    last_paid_timestamp: from_time_t(
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
                   10,002,000,000,000,000 wei owed for 2678400 sec exceeds threshold: 10,000,000,001,152,000 wei; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   999,999,999,000,000,000 wei owed for 86455 sec exceeds threshold: 999,978,993,055,555,580 wei; creditor: 0x0000000000000000000000000077616c6c657431");
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
}
