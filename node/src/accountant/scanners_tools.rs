// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_scanner_tools {
    use crate::accountant::payable_dao::{Payable, PayableAccount};
    use crate::accountant::SentPayable;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::sub_lib::accountant::PaymentThresholds;
    use masq_lib::logger::Logger;
    use masq_lib::utils::plus;
    use std::time::SystemTime;

    //for debugging only
    pub fn investigate_debt_extremes(
        timestamp: SystemTime,
        all_non_pending_payables: &[PayableAccount],
    ) -> String {
        if all_non_pending_payables.is_empty() {
            return "Payable scan found no debts".to_string();
        }
        #[derive(Clone, Copy, Default)]
        struct PayableInfo {
            balance: i64,
            age: u64,
        }

        fn bigger(payable_1: PayableInfo, payable_2: PayableInfo) -> PayableInfo {
            #[allow(clippy::comparison_chain)]
            if payable_1.balance > payable_2.balance {
                payable_1
            } else if payable_2.balance > payable_1.balance {
                payable_2
            } else {
                if payable_1.age != payable_2.age {
                    return older(payable_1, payable_2);
                }
                payable_1
            }
        }

        fn older(payable_1: PayableInfo, payable_2: PayableInfo) -> PayableInfo {
            #[allow(clippy::comparison_chain)]
            if payable_1.age > payable_2.age {
                payable_1
            } else if payable_2.age > payable_1.age {
                payable_2
            } else {
                if payable_1.balance != payable_2.balance {
                    return bigger(payable_1, payable_2);
                }
                payable_1
            }
        }

        let init = (PayableInfo::default(), PayableInfo::default());
        let (biggest, oldest) = all_non_pending_payables
            .iter()
            .map(|payable| PayableInfo {
                balance: payable.balance,
                age: payable_time_diff(timestamp, payable),
            })
            .fold(init, |so_far, payable| {
                let (mut biggest, mut oldest) = so_far;

                biggest = bigger(biggest, payable);
                oldest = older(oldest, payable);

                (biggest, oldest)
            });
        format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                all_non_pending_payables.len(), biggest.balance, biggest.age,
                oldest.balance, oldest.age)
    }

    pub fn is_payable_qualified(
        time: SystemTime,
        payable: &PayableAccount,
        payment_thresholds: &PaymentThresholds,
    ) -> Option<u64> {
        // TODO: This calculation should be done in the database, if possible
        let maturity_time_limit = payment_thresholds.maturity_threshold_sec as u64;
        let permanent_allowed_debt = payment_thresholds.permanent_debt_allowed_gwei;
        let time_since_last_paid = payable_time_diff(time, payable);
        let payable_balance = payable.balance;

        if time_since_last_paid <= maturity_time_limit {
            return None;
        }

        if payable_balance <= permanent_allowed_debt {
            return None;
        }

        let payout_threshold = calculate_payout_threshold(time_since_last_paid, payment_thresholds);
        if payable_balance as f64 <= payout_threshold {
            return None;
        }

        Some(payout_threshold as u64)
    }

    pub fn payable_time_diff(time: SystemTime, payable: &PayableAccount) -> u64 {
        time.duration_since(payable.last_paid_timestamp)
            .expect("Payable time is corrupt")
            .as_secs()
    }

    pub fn calculate_payout_threshold(x: u64, payment_thresholds: &PaymentThresholds) -> f64 {
        let m = -((payment_thresholds.debt_threshold_gwei as f64
            - payment_thresholds.permanent_debt_allowed_gwei as f64)
            / (payment_thresholds.threshold_interval_sec as f64
                - payment_thresholds.maturity_threshold_sec as f64));
        let b = payment_thresholds.debt_threshold_gwei as f64
            - m * payment_thresholds.maturity_threshold_sec as f64;
        m * x as f64 + b
    }

    pub fn exceeded_summary(time: SystemTime, payable: &PayableAccount, threshold: u64) -> String {
        format!(
            "{} owed for {}sec exceeds threshold: {}; creditor: {}\n",
            payable.balance,
            payable_time_diff(time, payable),
            threshold,
            payable.wallet.clone(),
        )
    }

    pub fn qualified_payables_and_summary(
        time: SystemTime,
        non_pending_payables: Vec<PayableAccount>,
        payment_thresholds: &PaymentThresholds,
    ) -> (Vec<PayableAccount>, String) {
        let mut qualified_summary = String::from("Paying qualified debts:\n");
        let mut qualified_payables: Vec<PayableAccount> = vec![];

        for payable in non_pending_payables {
            if let Some(threshold) = is_payable_qualified(time, &payable, payment_thresholds) {
                let payable_summary = exceeded_summary(time, &payable, threshold);
                qualified_summary.push_str(&payable_summary);
                qualified_payables.push(payable);
            }
        }

        let summary = match qualified_payables.is_empty() {
            true => String::from("No Qualified Payables found."),
            false => qualified_summary,
        };

        (qualified_payables, summary)
    }

    pub fn separate_early_errors(
        sent_payments: &SentPayable,
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
}

pub mod pending_payable_scanner_tools {
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

pub mod receivable_scanner_tools {
    use crate::accountant::receivable_dao::ReceivableAccount;
    use std::time::{Duration, SystemTime};

    pub fn balance_and_age(time: SystemTime, account: &ReceivableAccount) -> (String, Duration) {
        let balance = format!("{}", (account.balance as f64) / 1_000_000_000.0);
        let age = time
            .duration_since(account.last_received_timestamp)
            .unwrap_or_else(|_| Duration::new(0, 0));
        (balance, age)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payable_dao::{Payable, PayableAccount};
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::scanners_tools::payable_scanner_tools::{
        calculate_payout_threshold, exceeded_summary, investigate_debt_extremes,
        is_payable_qualified, payable_time_diff, qualified_payables_and_summary,
        separate_early_errors,
    };
    use crate::accountant::scanners_tools::receivable_scanner_tools::balance_and_age;
    use crate::accountant::test_utils::make_payables;
    use crate::accountant::SentPayable;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::rc::Rc;
    use std::time::SystemTime;

    #[test]
    fn payable_generated_within_maturity_time_limit_is_marked_unqualified() {
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let qualified_debt = payment_thresholds.permanent_debt_allowed_gwei + 1;
        let unqualified_time = to_time_t(now) - payment_thresholds.maturity_threshold_sec + 1;
        let unqualified_payable_account = PayableAccount {
            wallet: make_wallet("wallet0"),
            balance: qualified_debt,
            last_paid_timestamp: from_time_t(unqualified_time),
            pending_payable_opt: None,
        };

        let result = is_payable_qualified(now, &unqualified_payable_account, &payment_thresholds);

        assert_eq!(result, None);
    }

    #[test]
    fn payable_with_debt_under_the_slope_is_marked_unqualified() {
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let unqualified_debt = payment_thresholds.permanent_debt_allowed_gwei - 1;
        let qualified_time = to_time_t(now) - payment_thresholds.maturity_threshold_sec - 1;
        let unqualified_payable_account = PayableAccount {
            wallet: make_wallet("wallet0"),
            balance: unqualified_debt,
            last_paid_timestamp: from_time_t(qualified_time),
            pending_payable_opt: None,
        };

        let result = is_payable_qualified(now, &unqualified_payable_account, &payment_thresholds);

        assert_eq!(result, None);
    }

    #[test]
    fn payable_with_low_payout_threshold_is_marked_unqualified() {
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let debt = payment_thresholds.permanent_debt_allowed_gwei + 1;
        let time = to_time_t(now) - payment_thresholds.maturity_threshold_sec - 1;
        let unqualified_payable_account = PayableAccount {
            wallet: make_wallet("wallet0"),
            balance: debt,
            last_paid_timestamp: from_time_t(time),
            pending_payable_opt: None,
        };

        let result = is_payable_qualified(now, &unqualified_payable_account, &payment_thresholds);

        assert_eq!(result, None);
    }

    #[test]
    fn payable_with_debt_above_the_slope_is_qualified_and_the_threshold_value_is_returned() {
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let debt = payment_thresholds.debt_threshold_gwei - 1;
        let time = payment_thresholds.maturity_threshold_sec
            + payment_thresholds.threshold_interval_sec
            - 1;
        let payment_thresholds_rc = Rc::new(payment_thresholds);
        let qualified_payable = PayableAccount {
            wallet: make_wallet("wallet0"),
            balance: debt,
            last_paid_timestamp: from_time_t(time),
            pending_payable_opt: None,
        };
        let threshold = calculate_payout_threshold(
            payable_time_diff(now, &qualified_payable),
            &payment_thresholds_rc,
        );

        let result = is_payable_qualified(now, &qualified_payable, &payment_thresholds_rc);

        assert_eq!(result, Some(threshold as u64));
    }

    #[test]
    fn qualified_payables_can_be_filtered_out_from_non_pending_payables_along_with_their_summary() {
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let (qualified_payable_accounts, _, all_non_pending_payables) =
            make_payables(now, &PaymentThresholds::default());

        let (qualified_payables, summary) =
            qualified_payables_and_summary(now, all_non_pending_payables, &payment_thresholds);

        let mut expected_summary = String::from("Paying qualified debts:\n");
        for payable in qualified_payable_accounts.iter() {
            expected_summary.push_str(&exceeded_summary(
                now,
                &payable,
                calculate_payout_threshold(payable_time_diff(now, &payable), &payment_thresholds)
                    as u64,
            ))
        }
        assert_eq!(qualified_payables, qualified_payable_accounts);
        assert_eq!(summary, expected_summary);
    }

    #[test]
    fn returns_an_empty_vector_and_summary_when_no_qualified_payables_are_found() {
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let unqualified_payable_accounts = vec![PayableAccount {
            wallet: make_wallet("wallet1"),
            balance: payment_thresholds.permanent_debt_allowed_gwei + 1,
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec + 1,
            ),
            pending_payable_opt: None,
        }];

        let (qualified_payables, summary) =
            qualified_payables_and_summary(now, unqualified_payable_accounts, &payment_thresholds);

        assert_eq!(qualified_payables, vec![]);
        assert_eq!(summary, String::from("No Qualified Payables found."));
    }

    #[test]
    fn investigate_debt_extremes_picks_the_most_relevant_records() {
        let now = SystemTime::now();
        let now_t = to_time_t(now);
        let same_amount_significance = 2_000_000;
        let same_age_significance = from_time_t(now_t - 30000);
        let payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now_t - 5000),
                pending_payable_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now_t - 10000),
                pending_payable_opt: None,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance: 100,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: 330,
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
            balance: 10_000_000_000,
            last_received_timestamp: from_time_t(to_time_t(now) - offset),
        };

        let (balance, age) = balance_and_age(now, &receivable_account);

        assert_eq!(balance, "10");
        assert_eq!(age.as_secs(), offset as u64);
    }

    #[test]
    fn separate_early_errors_works() {
        init_test_logging();
        let test_name = "separate_early_errors_works";
        let payable_ok = Payable {
            to: make_wallet("blah"),
            amount: 5555,
            timestamp: SystemTime::now(),
            tx_hash: Default::default(),
        };
        let error = BlockchainError::SignedValueConversion(666);
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![Ok(payable_ok.clone()), Err(error.clone())],
            response_skeleton_opt: None,
        };

        let (ok, err) = separate_early_errors(&sent_payable, &Logger::new(test_name));

        assert_eq!(ok, vec![payable_ok]);
        assert_eq!(err, vec![error.clone()]);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {}: Outbound transaction failure due to '{:?}",
            test_name, error
        ));
    }
}
