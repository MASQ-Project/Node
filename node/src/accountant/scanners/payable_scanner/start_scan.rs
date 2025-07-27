use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition;
use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition::ByAddresses;
use crate::accountant::db_access_objects::utils::from_unix_timestamp;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    QualifiedPayablesBeforeGasPriceSelection, QualifiedPayablesMessage, UnpricedQualifiedPayables,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::investigate_debt_extremes;
use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
use crate::accountant::{ResponseSkeleton, ScanForNewPayables, ScanForRetryPayables};
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use std::collections::BTreeSet;
use std::time::SystemTime;
use web3::types::Address;

impl StartableScanner<ScanForNewPayables, QualifiedPayablesMessage> for PayableScanner {
    fn start_scan(
        &mut self,
        consuming_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for new payables");
        let all_non_pending_payables = self.payable_dao.non_pending_payables(None);

        debug!(
            logger,
            "{}",
            investigate_debt_extremes(timestamp, &all_non_pending_payables)
        );

        let qualified_payables =
            self.sniff_out_alarming_payables_and_maybe_log_them(all_non_pending_payables, logger);

        match qualified_payables.is_empty() {
            true => {
                self.mark_as_ended(logger);
                Err(StartScanError::NothingToProcess)
            }
            false => {
                info!(
                    logger,
                    "Chose {} qualified debts to pay",
                    qualified_payables.len()
                );
                let qualified_payables = UnpricedQualifiedPayables::from(qualified_payables);
                let outgoing_msg = QualifiedPayablesMessage::new(
                    qualified_payables,
                    consuming_wallet.clone(),
                    response_skeleton_opt,
                );
                Ok(outgoing_msg)
            }
        }
    }
}

impl StartableScanner<ScanForRetryPayables, QualifiedPayablesMessage> for PayableScanner {
    fn start_scan(
        &mut self,
        consuming_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for retry payables");
        let failed_txs = self
            .failed_payable_dao
            .retrieve_txs(Some(ByStatus(RetryRequired)));
        let addresses: BTreeSet<Address> = failed_txs
            .iter()
            .map(|failed_tx| failed_tx.receiver_address)
            .collect();
        let non_pending_payables = self
            .payable_dao
            .non_pending_payables(Some(ByAddresses(addresses)));

        let payables = failed_txs
            .iter()
            .filter_map(|failed_tx| {
                non_pending_payables
                    .iter()
                    .find(|payable| payable.wallet.address() == failed_tx.receiver_address)
                    .map(|payable| QualifiedPayablesBeforeGasPriceSelection {
                        payable: PayableAccount {
                            wallet: payable.wallet.clone(),
                            balance_wei: payable.balance_wei + failed_tx.amount,
                            last_paid_timestamp: payable.last_paid_timestamp,
                            pending_payable_opt: payable.pending_payable_opt,
                        },
                        previous_attempt_gas_price_minor_opt: Some(failed_tx.gas_price_wei),
                    })
            })
            .collect();
        // TODO: Instead of filter map, use map so that you won't miss any cases

        Ok(QualifiedPayablesMessage {
            qualified_payables: UnpricedQualifiedPayables { payables },
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt,
        })
        // 1. Find the failed payables
        // 2. Look into the payable DAO to update the amount
        // 3. Prepare UnpricedQualifiedPayables

        // 1. Fetch all records with RetryRequired
        // 2. Query the txs with the same accounts from the PayableDao
        // 3. Form UnpricedQualifiedPayables, a collection vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::PendingTooLong;
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDao, FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition::ByAddresses;
    use crate::accountant::db_access_objects::payable_dao::{
        PayableAccount, PayableDao, PayableRetrieveCondition,
    };
    use crate::accountant::db_access_objects::test_utils::FailedTxBuilder;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner_extension::msgs::QualifiedPayablesBeforeGasPriceSelection;
    use crate::accountant::scanners::Scanners;
    use crate::accountant::test_utils::{
        make_payable_account, FailedPayableDaoMock, PayableDaoMock,
    };
    use crate::accountant::PendingPayableId;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_paying_wallet;
    use actix::System;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn start_scan_for_retry_works() {
        init_test_logging();
        let test_name = "start_scan_for_retry_works";
        let logger = Logger::new(test_name);
        let failed_payables_retrieve_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let timestamp = SystemTime::now();
        let client_id = 1234;
        let context_id = 4321;
        let tx_hash_1 = make_tx_hash(1);
        let payable_amount = 42;
        let payable_account = make_payable_account(payable_amount);
        let receiver_address = payable_account.wallet.address();
        let failed_tx_1 = FailedTxBuilder::default()
            .nonce(1)
            .hash(tx_hash_1)
            .receiver_address(receiver_address)
            .reason(PendingTooLong)
            .status(RetryRequired)
            .build();
        let addresses = BTreeSet::from([receiver_address]);
        let consuming_wallet = make_paying_wallet(b"consuming");
        let failed_payable_dao = FailedPayableDaoMock::new()
            .retrieve_txs_params(&failed_payables_retrieve_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1.clone()]);
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![payable_account.clone()]);
        let mut subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .payable_dao(payable_dao)
            .build();
        let system = System::new(test_name);

        let result = Scanners::start_correct_payable_scanner::<ScanForRetryPayables>(
            &mut subject,
            &consuming_wallet,
            timestamp,
            Some(ResponseSkeleton {
                client_id,
                context_id,
            }),
            &logger,
        );

        System::current().stop();
        let scan_started_at = subject.scan_started_at();
        let failed_payables_retrieve_txs_params =
            failed_payables_retrieve_txs_params_arc.lock().unwrap();
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        let mut new_payable_account = payable_account;
        new_payable_account.balance_wei = new_payable_account.balance_wei + failed_tx_1.amount;
        assert_eq!(
            result,
            Ok(QualifiedPayablesMessage {
                qualified_payables: UnpricedQualifiedPayables {
                    payables: vec![QualifiedPayablesBeforeGasPriceSelection {
                        payable: new_payable_account,
                        previous_attempt_gas_price_minor_opt: Some(failed_tx_1.gas_price_wei),
                    }]
                },
                consuming_wallet: consuming_wallet.clone(),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id,
                    context_id,
                }),
            })
        );
        assert_eq!(scan_started_at, Some(timestamp));
        assert_eq!(
            failed_payables_retrieve_txs_params[0],
            Some(ByStatus(FailureStatus::RetryRequired))
        );
        assert_eq!(
            non_pending_payables_params[0],
            Some(PayableRetrieveCondition::ByAddresses(addresses))
        );
        TestLogHandler::new()
            .exists_log_containing(&format!("INFO: {test_name}: Scanning for retry payables"));
    }
}
