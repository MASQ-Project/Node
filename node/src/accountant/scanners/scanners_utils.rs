// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_scanner_utils {
    use crate::accountant::db_access_objects::utils::{ThresholdUtils, TxHash};
    use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDaoError};
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
        LocallyCausedError, RemotelyCausedErrors,
    };
    use crate::accountant::{comma_joined_stringifiable, PendingPayable, SentPayables};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::sub_lib::wallet::Wallet;
    use itertools::Itertools;
    use masq_lib::logger::Logger;
    use std::cmp::Ordering;
    use std::collections::HashSet;
    use std::ops::Not;
    use std::time::SystemTime;
    use thousands::Separable;
    use web3::types::{Address, H256};
    use masq_lib::ui_gateway::NodeToUiMessage;
    use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError;
    use crate::blockchain::blockchain_interface::data_structures::{ProcessedPayableFallible, RpcPayableFailure};

    #[derive(Debug, PartialEq, Eq)]
    pub enum PayableTransactingErrorEnum {
        LocallyCausedError(PayableTransactionError),
        RemotelyCausedErrors(HashSet<TxHash>),
    }

    #[derive(Debug, PartialEq)]
    pub struct PayableScanResult {
        pub ui_response_opt: Option<NodeToUiMessage>,
        pub result: OperationOutcome,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum OperationOutcome {
        NewPendingPayable,
        Failure,
    }

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

    // TODO lifetimes simplification???
    pub fn separate_errors<'a, 'b>(
        sent_payables: &'a SentPayables,
        logger: &'b Logger,
    ) -> (Vec<&'a PendingPayable>, Option<PayableTransactingErrorEnum>) {
        match &sent_payables.payment_procedure_result {
            Ok(individual_batch_responses) => {
                if individual_batch_responses.is_empty() {
                    panic!("Broken code: An empty vector of processed payments claiming to be an Ok value")
                }

                let separated_txs_by_result =
                    separate_rpc_results(individual_batch_responses, logger);

                let remote_errs_opt = if separated_txs_by_result.err_results.is_empty() {
                    None
                } else {
                    warning!(
                        logger,
                        "Please check your blockchain service URL configuration due \
                    to detected remote failures"
                    );
                    Some(RemotelyCausedErrors(separated_txs_by_result.err_results))
                };
                let oks = separated_txs_by_result.ok_results;

                (oks, remote_errs_opt)
            }
            Err(e) => {
                warning!(
                    logger,
                    "Any persisted data from the failed process will be deleted. Caused by: {}",
                    e
                );

                (vec![], Some(LocallyCausedError(e.clone())))
            }
        }
    }

    fn separate_rpc_results<'a>(
        batch_request_responses: &'a [ProcessedPayableFallible],
        logger: &Logger,
    ) -> SeparatedTxsByResult<'a> {
        //TODO maybe we can return not tuple but struct with remote_errors_opt member
        let init = SeparatedTxsByResult::default();
        batch_request_responses
            .iter()
            .fold(init, |acc, rpc_result| {
                separate_rpc_results_fold_guts(acc, rpc_result, logger)
            })
    }

    #[derive(Default)]
    pub struct SeparatedTxsByResult<'a> {
        pub ok_results: Vec<&'a PendingPayable>,
        pub err_results: HashSet<TxHash>,
    }

    fn separate_rpc_results_fold_guts<'a>(
        mut acc: SeparatedTxsByResult<'a>,
        rpc_result: &'a ProcessedPayableFallible,
        logger: &Logger,
    ) -> SeparatedTxsByResult<'a> {
        match rpc_result {
            ProcessedPayableFallible::Correct(pending_payable) => {
                acc.ok_results.push(pending_payable);
                acc
            }
            ProcessedPayableFallible::Failed(RpcPayableFailure {
                rpc_error,
                recipient_wallet,
                hash,
            }) => {
                warning!(
                    logger,
                    "Remote sent payable failure '{}' for wallet {} and tx hash {:?}",
                    rpc_error,
                    recipient_wallet,
                    hash
                );
                acc.err_results.insert(*hash);
                acc
            }
        }
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
                        "{} wei owed for {} sec exceeds the threshold {} wei for creditor {}",
                        payable.balance_wei.separate_with_commas(),
                        p_age.as_secs(),
                        threshold_point.separate_with_commas(),
                        payable.wallet
                    )
                })
                .join(".\n")
        })
    }

    pub fn debugging_summary_after_error_separation(
        oks: &[&PendingPayable],
        errs_opt: &Option<PayableTransactingErrorEnum>,
    ) -> String {
        format!(
            "Got {} properly sent payables of {} attempts",
            oks.len(),
            count_total_errors(errs_opt)
                .map(|err_count| (err_count + oks.len()).to_string())
                .unwrap_or_else(|| "an unknown number of".to_string())
        )
    }

    pub(super) fn count_total_errors(
        full_set_of_errors: &Option<PayableTransactingErrorEnum>,
    ) -> Option<usize> {
        match full_set_of_errors {
            Some(errors) => match errors {
                LocallyCausedError(blockchain_error) => match blockchain_error {
                    PayableTransactionError::Sending { hashes, .. } => Some(hashes.len()),
                    _ => None,
                },
                RemotelyCausedErrors(hashes) => Some(hashes.len()),
            },
            None => Some(0),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct PendingPayableMissingInDb {
        pub recipient: Address,
        pub hash: H256,
    }

    impl PendingPayableMissingInDb {
        pub fn new(recipient: Address, hash: H256) -> PendingPayableMissingInDb {
            PendingPayableMissingInDb { recipient, hash }
        }
    }

    // pub fn mark_pending_payable_fatal_error(
    //     sent_payments: &[&PendingPayable],
    //     nonexistent: &[PendingPayableMissingInDb],
    //     error: PayableDaoError,
    //     missing_fingerprints_msg_maker: fn(&[PendingPayableMissingInDb]) -> String,
    //     logger: &Logger,
    // ) {
    //     if !nonexistent.is_empty() {
    //         error!(logger, "{}", missing_fingerprints_msg_maker(nonexistent))
    //     };
    //     panic!(
    //         "Unable to create a mark in the payable table for wallets {} due to {:?}",
    //         comma_joined_stringifiable(sent_payments, |pending_p| pending_p
    //             .recipient_wallet
    //             .to_string()),
    //         error
    //     )
    // }

    pub fn err_msg_for_failure_with_expected_but_missing_sent_tx_record(
        nonexistent: Vec<H256>,
        serialize_hashes: fn(&[H256]) -> String,
    ) -> Option<String> {
        nonexistent.is_empty().not().then_some(format!(
            "Ran into failed payables {} with missing records. The system has become unreliable",
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
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::db_access_objects::payable_dao::{PayableAccount};
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
        LocallyCausedError, RemotelyCausedErrors,
    };
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{
        count_total_errors, debugging_summary_after_error_separation, investigate_debt_extremes,
        payables_debug_summary, separate_errors, PayableThresholdsGauge,
        PayableThresholdsGaugeReal,
    };
    use crate::accountant::{checked_conversion, gwei_to_wei, PendingPayable, SentPayables};
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use masq_lib::constants::WEIS_IN_GWEI;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::{Duration, SystemTime};
    use itertools::Itertools;
    use regex::Regex;
    use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason, FailureStatus, ValidationStatus};
    use crate::accountant::db_access_objects::sent_payable_dao::{SentTx, TxStatus};
    use crate::assert_on_testing_enum_with_all_its_variants;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::BlockchainTxFailure;
    use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainError, PayableTransactionError};
    use crate::blockchain::blockchain_interface::data_structures::{ProcessedPayableFallible, RpcPayableFailure};
    use crate::blockchain::errors::{AppRpcError, LocalError, RemoteError};

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
    fn separate_errors_works_for_no_errs_just_oks() {
        let correct_payment_1 = PendingPayable {
            recipient_wallet: make_wallet("blah"),
            hash: make_tx_hash(123),
        };
        let correct_payment_2 = PendingPayable {
            recipient_wallet: make_wallet("howgh"),
            hash: make_tx_hash(456),
        };
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![
                ProcessedPayableFallible::Correct(correct_payment_1.clone()),
                ProcessedPayableFallible::Correct(correct_payment_2.clone()),
            ]),
            response_skeleton_opt: None,
        };

        let (oks, errs) = separate_errors(&sent_payable, &Logger::new("test"));

        assert_eq!(oks, vec![&correct_payment_1, &correct_payment_2]);
        assert_eq!(errs, None)
    }

    #[test]
    fn separate_errors_works_for_local_error() {
        init_test_logging();
        let error = PayableTransactionError::Sending {
            msg: "Bad luck".to_string(),
            hashes: hashset![make_tx_hash(0x7b)],
        };
        let sent_payable = SentPayables {
            payment_procedure_result: Err(error.clone()),
            response_skeleton_opt: None,
        };

        let (oks, errs) = separate_errors(&sent_payable, &Logger::new("test_logger"));

        assert!(oks.is_empty());
        assert_eq!(errs, Some(LocallyCausedError(error)));
        TestLogHandler::new().exists_log_containing(
            "WARN: test_logger: Any persisted data from \
        the failed process will be deleted. Caused by: Sending phase: \"Bad luck\". Signed and hashed txs: \
        0x000000000000000000000000000000000000000000000000000000000000007b",
        );
    }

    #[test]
    fn separate_errors_works_for_their_errors() {
        init_test_logging();
        let payable_ok = PendingPayable {
            recipient_wallet: make_wallet("blah"),
            hash: make_tx_hash(123),
        };
        let bad_rpc_call = RpcPayableFailure {
            rpc_error: web3::Error::InvalidResponse("That jackass screwed it up".to_string()),
            recipient_wallet: make_wallet("whooa"),
            hash: make_tx_hash(0x315),
        };
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![
                ProcessedPayableFallible::Correct(payable_ok.clone()),
                ProcessedPayableFallible::Failed(bad_rpc_call.clone()),
            ]),
            response_skeleton_opt: None,
        };

        let (oks, errs) = separate_errors(&sent_payable, &Logger::new("test_logger"));

        assert_eq!(oks, vec![&payable_ok]);
        assert_eq!(
            errs,
            Some(RemotelyCausedErrors(hashset![make_tx_hash(0x315)]))
        );
        TestLogHandler::new().exists_log_containing("WARN: test_logger: Remote sent payable \
        failure 'Got invalid response: That jackass screwed it up' for wallet 0x00000000000000000000\
        000000000077686f6f61 and tx hash 0x000000000000000000000000000000000000000000000000000000000\
        0000315");
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
                   10,002,000,000,000,000 wei owed for 2678400 sec exceeds the threshold \
                   10,000,000,001,152,000 wei for creditor 0x0000000000000000000000000077616c6c657430.\n\
                   999,999,999,000,000,000 wei owed for 86455 sec exceeds the threshold \
                   999,978,993,055,555,580 wei for creditor 0x0000000000000000000000000077616c6c657431");
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
    fn conversion_between_blockchain_tx_failure_and_failure_reason_works() {
        let input_and_expected_results =
            vec![(BlockchainTxFailure::Unrecognized, FailureReason::Reverted)];
        let inputs_len = input_and_expected_results.len();

        let check_nums = input_and_expected_results
            .into_iter()
            .map(|(input, failure_reason)| match input {
                BlockchainTxFailure::Unrecognized => {
                    let result = FailureReason::from(input);
                    assert_eq!(result, failure_reason);
                    1
                }
            })
            .collect_vec();

        assert_on_testing_enum_with_all_its_variants!(BlockchainTxFailure, check_nums, inputs_len)
    }

    #[test]
    fn conversion_from_sent_tx_and_failure_reason_to_failed_tx_works() {
        let sent_tx = SentTx {
            hash: make_tx_hash(789),
            receiver_address: make_wallet("receiver").address(),
            amount_minor: 123_456_789,
            timestamp: to_unix_timestamp(
                SystemTime::now()
                    .checked_sub(Duration::from_secs(10_000))
                    .unwrap(),
            ),
            gas_price_minor: gwei_to_wei(424_u64),
            nonce: 456_u64.into(),
            status: TxStatus::Pending(ValidationStatus::Waiting),
        };

        let result_1 = FailedTx::from((sent_tx.clone(), FailureReason::Reverted));
        let result_2 = FailedTx::from((
            sent_tx.clone(),
            FailureReason::Submission(AppRpcError::Local(LocalError::Internal)),
        ));

        assert_conversion_into_failed_tx(result_1, sent_tx.clone(), FailureReason::Reverted);
        assert_conversion_into_failed_tx(
            result_2,
            sent_tx,
            FailureReason::Submission(AppRpcError::Local(LocalError::Internal)),
        );
    }

    fn assert_conversion_into_failed_tx(
        result: FailedTx,
        original_sent_tx: SentTx,
        expected_failure_reason: FailureReason,
    ) {
        assert_eq!(result.hash, original_sent_tx.hash);
        assert_eq!(result.receiver_address, original_sent_tx.receiver_address);
        assert_eq!(result.amount_minor, original_sent_tx.amount_minor);
        assert_eq!(result.timestamp, original_sent_tx.timestamp);
        assert_eq!(result.gas_price_minor, original_sent_tx.gas_price_minor);
        assert_eq!(result.nonce, original_sent_tx.nonce);
        assert_eq!(result.status, FailureStatus::RetryRequired);
        assert_eq!(result.reason, expected_failure_reason);
    }

    #[test]
    fn count_total_errors_says_unknown_number_for_early_local_errors() {
        let early_local_errors = [
            PayableTransactionError::TransactionID(BlockchainError::QueryFailed(
                "blah".to_string(),
            )),
            PayableTransactionError::MissingConsumingWallet,
            PayableTransactionError::GasPriceQueryFailed(BlockchainError::QueryFailed(
                "ouch".to_string(),
            )),
            PayableTransactionError::UnusableWallet("fooo".to_string()),
            PayableTransactionError::Signing("tsss".to_string()),
        ];

        early_local_errors
            .into_iter()
            .for_each(|err| assert_eq!(count_total_errors(&Some(LocallyCausedError(err))), None))
    }

    #[test]
    fn count_total_errors_works_correctly_for_local_error_after_signing() {
        let error = PayableTransactionError::Sending {
            msg: "Ouuuups".to_string(),
            hashes: hashset![make_tx_hash(333), make_tx_hash(666)],
        };
        let sent_payable = Some(LocallyCausedError(error));

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, Some(2))
    }

    #[test]
    fn count_total_errors_works_correctly_for_remote_errors() {
        let sent_payable = Some(RemotelyCausedErrors(hashset![
            make_tx_hash(123),
            make_tx_hash(456),
        ]));

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, Some(2))
    }

    #[test]
    fn count_total_errors_works_correctly_if_no_errors_found_at_all() {
        let sent_payable = None;

        let result = count_total_errors(&sent_payable);

        assert_eq!(result, Some(0))
    }

    #[test]
    fn debug_summary_after_error_separation_says_the_count_cannot_be_known() {
        let oks = vec![];
        let error = PayableTransactionError::MissingConsumingWallet;
        let errs = Some(LocallyCausedError(error));

        let result = debugging_summary_after_error_separation(&oks, &errs);

        assert_eq!(
            result,
            "Got 0 properly sent payables of an unknown number of attempts"
        )
    }
}
