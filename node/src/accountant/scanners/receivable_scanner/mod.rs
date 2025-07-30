// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::accountant::db_access_objects::banned_dao::BannedDao;
use crate::accountant::db_access_objects::receivable_dao::ReceivableDao;
use crate::accountant::scanners::receivable_scanner::utils::balance_and_age;
use crate::accountant::scanners::{
    PrivateScanner, Scanner, ScannerCommon, StartScanError, StartableScanner,
};
use crate::accountant::{ReceivedPayments, ResponseSkeleton, ScanForReceivables};
use crate::blockchain::blockchain_bridge::{BlockMarker, RetrieveTransactions};
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::time_marking_methods;
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::SystemTime;

pub struct ReceivableScanner {
    pub common: ScannerCommon,
    pub receivable_dao: Box<dyn ReceivableDao>,
    pub banned_dao: Box<dyn BannedDao>,
    pub persistent_configuration: Box<dyn PersistentConfiguration>,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
}

impl
    PrivateScanner<
        ScanForReceivables,
        RetrieveTransactions,
        ReceivedPayments,
        Option<NodeToUiMessage>,
    > for ReceivableScanner
{
}

impl StartableScanner<ScanForReceivables, RetrieveTransactions> for ReceivableScanner {
    fn start_scan(
        &mut self,
        earning_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<RetrieveTransactions, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for receivables to {}", earning_wallet);
        self.scan_for_delinquencies(timestamp, logger);

        Ok(RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt,
        })
    }
}

impl Scanner<ReceivedPayments, Option<NodeToUiMessage>> for ReceivableScanner {
    fn finish_scan(&mut self, msg: ReceivedPayments, logger: &Logger) -> Option<NodeToUiMessage> {
        self.handle_new_received_payments(&msg, logger);
        self.mark_as_ended(logger);

        msg.response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    time_marking_methods!(Receivables);

    as_any_ref_in_trait_impl!();
    as_any_mut_in_trait_impl!();
}

impl ReceivableScanner {
    pub fn new(
        receivable_dao: Box<dyn ReceivableDao>,
        banned_dao: Box<dyn BannedDao>,
        persistent_configuration: Box<dyn PersistentConfiguration>,
        payment_thresholds: Rc<PaymentThresholds>,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            receivable_dao,
            banned_dao,
            persistent_configuration,
            financial_statistics,
        }
    }

    fn handle_new_received_payments(
        &mut self,
        received_payments_msg: &ReceivedPayments,
        logger: &Logger,
    ) {
        if received_payments_msg.transactions.is_empty() {
            info!(
                logger,
                "No newly received payments were detected during the scanning process."
            );
            let new_start_block = received_payments_msg.new_start_block;
            if let BlockMarker::Value(start_block_number) = new_start_block {
                match self
                    .persistent_configuration
                    .set_start_block(Some(start_block_number))
                {
                    Ok(()) => debug!(logger, "Start block updated to {}", start_block_number),
                    Err(e) => panic!(
                        "Attempt to set new start block to {} failed due to: {:?}",
                        start_block_number, e
                    ),
                }
            }
        } else {
            let mut txn = self.receivable_dao.as_mut().more_money_received(
                received_payments_msg.timestamp,
                &received_payments_msg.transactions,
            );
            let new_start_block = received_payments_msg.new_start_block;
            if let BlockMarker::Value(start_block_number) = new_start_block {
                match self
                    .persistent_configuration
                    .set_start_block_from_txn(Some(start_block_number), &mut txn)
                {
                    Ok(()) => debug!(logger, "Start block updated to {}", start_block_number),
                    Err(e) => panic!(
                        "Attempt to set new start block to {} failed due to: {:?}",
                        start_block_number, e
                    ),
                }
            } else {
                unreachable!("Failed to get start_block while transactions were present");
            }
            match txn.commit() {
                Ok(_) => {
                    debug!(logger, "Received payments have been commited to database");
                }
                Err(e) => panic!("Commit of received transactions failed: {:?}", e),
            }
            let total_newly_paid_receivable = received_payments_msg
                .transactions
                .iter()
                .fold(0, |so_far, now| so_far + now.wei_amount);

            self.financial_statistics
                .borrow_mut()
                .total_paid_receivable_wei += total_newly_paid_receivable;
        }
    }

    pub fn scan_for_delinquencies(&self, timestamp: SystemTime, logger: &Logger) {
        info!(logger, "Scanning for delinquencies");
        self.find_and_ban_delinquents(timestamp, logger);
        self.find_and_unban_reformed_nodes(timestamp, logger);
    }

    fn find_and_ban_delinquents(&self, timestamp: SystemTime, logger: &Logger) {
        self.receivable_dao
            .new_delinquencies(timestamp, self.common.payment_thresholds.as_ref())
            .into_iter()
            .for_each(|account| {
                self.banned_dao.ban(&account.wallet);
                let (balance_str_wei, age) = balance_and_age(timestamp, &account);
                info!(
                    logger,
                    "Wallet {} (balance: {} gwei, age: {} sec) banned for delinquency",
                    account.wallet,
                    balance_str_wei,
                    age.as_secs()
                )
            });
    }

    fn find_and_unban_reformed_nodes(&self, timestamp: SystemTime, logger: &Logger) {
        self.receivable_dao
            .paid_delinquencies(self.common.payment_thresholds.as_ref())
            .into_iter()
            .for_each(|account| {
                self.banned_dao.unban(&account.wallet);
                let (balance_str_wei, age) = balance_and_age(timestamp, &account);
                info!(
                    logger,
                    "Wallet {} (balance: {} gwei, age: {} sec) is no longer delinquent: unbanned",
                    account.wallet,
                    balance_str_wei,
                    age.as_secs()
                )
            });
    }
}
