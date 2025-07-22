use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::test_utils::{
    FailedPayableDaoMock, PayableDaoMock, PaymentAdjusterMock, SentPayableDaoMock,
};
use crate::blockchain::blockchain_interface::data_structures::RpcPayableFailure;
use crate::blockchain::test_utils::make_tx_hash;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::test_utils::make_wallet;
use std::rc::Rc;

pub struct PayableScannerBuilder {
    payable_dao: PayableDaoMock,
    sent_payable_dao: SentPayableDaoMock,
    failed_payable_dao: FailedPayableDaoMock,
    payment_thresholds: PaymentThresholds,
    payment_adjuster: PaymentAdjusterMock,
}

impl PayableScannerBuilder {
    pub fn new() -> Self {
        Self {
            payable_dao: PayableDaoMock::new(),
            sent_payable_dao: SentPayableDaoMock::new(),
            failed_payable_dao: FailedPayableDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            payment_adjuster: PaymentAdjusterMock::default(),
        }
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> PayableScannerBuilder {
        self.payable_dao = payable_dao;
        self
    }

    pub fn sent_payable_dao(
        mut self,
        sent_payable_dao: SentPayableDaoMock,
    ) -> PayableScannerBuilder {
        self.sent_payable_dao = sent_payable_dao;
        self
    }

    pub fn failed_payable_dao(
        mut self,
        failed_payable_dao: FailedPayableDaoMock,
    ) -> PayableScannerBuilder {
        self.failed_payable_dao = failed_payable_dao;
        self
    }

    pub fn payment_adjuster(
        mut self,
        payment_adjuster: PaymentAdjusterMock,
    ) -> PayableScannerBuilder {
        self.payment_adjuster = payment_adjuster;
        self
    }

    pub fn payment_thresholds(mut self, payment_thresholds: PaymentThresholds) -> Self {
        self.payment_thresholds = payment_thresholds;
        self
    }

    pub fn build(self) -> PayableScanner {
        PayableScanner::new(
            Box::new(self.payable_dao),
            Box::new(self.sent_payable_dao),
            Box::new(self.failed_payable_dao),
            Rc::new(self.payment_thresholds),
            Box::new(self.payment_adjuster),
        )
    }
}

pub fn make_pending_payable(n: u32) -> PendingPayable {
    PendingPayable {
        recipient_wallet: make_wallet(&format!("pending_payable_recipient_{n}")),
        hash: make_tx_hash(n * 4724927),
    }
}

pub fn make_rpc_payable_failure(n: u32) -> RpcPayableFailure {
    RpcPayableFailure {
        recipient_wallet: make_wallet(&format!("rpc_payable_failure_recipient_{n}")),
        hash: make_tx_hash(n * 234819),
        rpc_error: web3::Error::Rpc(jsonrpc_core::Error::internal_error()),
    }
}
