#![cfg(test)]

use crate::accountant::scanners::payable_scanner::msgs::PricedTemplatesMessage;
use crate::accountant::scanners::payable_scanner::{PayableScanner, PreparedAdjustment};
use crate::accountant::test_utils::{
    FailedPayableDaoMock, PayableDaoMock, PaymentAdjusterMock, SentPayableDaoMock,
};
use crate::blockchain::blockchain_agent::test_utils::BlockchainAgentMock;
use crate::sub_lib::accountant::PaymentThresholds;
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

impl Clone for PricedTemplatesMessage {
    fn clone(&self) -> Self {
        let original_agent_id = self.agent.arbitrary_id_stamp();
        let cloned_agent = BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
        Self {
            priced_templates: self.priced_templates.clone(),
            agent: Box::new(cloned_agent),
            response_skeleton_opt: self.response_skeleton_opt,
        }
    }
}

impl Clone for PreparedAdjustment {
    fn clone(&self) -> Self {
        Self {
            original_setup_msg: self.original_setup_msg.clone(),
            adjustment: self.adjustment.clone(),
        }
    }
}
