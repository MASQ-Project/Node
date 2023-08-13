// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::setup_msg::PayablePaymentsSetupMsg;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;
use std::time::SystemTime;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &PayablePaymentsSetupMsg,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError>;

    fn adjust_payments(
        &self,
        setup: PreparedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        _msg: &PayablePaymentsSetupMsg,
        _logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError> {
        Ok(None)
    }

    fn adjust_payments(
        &self,
        _setup: PreparedAdjustment,
        _now: SystemTime,
        _logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        todo!("this function is dead until the card GH-711 is played")
    }

    implement_as_any!();
}

impl PaymentAdjusterReal {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for PaymentAdjusterReal {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Adjustment {
    MasqToken,
    TransactionFeeCurrency { limiting_count: u16 },
    Both,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::{PaymentAdjuster, PaymentAdjusterReal};
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::setup_msg::{
        PayablePaymentsSetupMsg, QualifiedPayablesMessage,
    };
    use crate::accountant::test_utils::{make_payable_account, PayablePaymentsAgentMock};
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

    #[test]
    fn search_for_indispensable_adjustment_always_returns_none() {
        init_test_logging();
        let test_name = "is_adjustment_required_always_returns_none";
        let mut payable = make_payable_account(111);
        payable.balance_wei = 100_000_000;
        let agent = PayablePaymentsAgentMock::default();
        let setup_msg = PayablePaymentsSetupMsg {
            payables: QualifiedPayablesMessage {
                qualified_payables: vec![payable],
                response_skeleton_opt: None,
            },
            agent: Box::new(agent),
        };
        let logger = Logger::new(test_name);
        let subject = PaymentAdjusterReal::new();

        let result = subject.search_for_indispensable_adjustment(&setup_msg, &logger);

        assert_eq!(result, Ok(None));
        TestLogHandler::default().exists_no_log_containing(test_name);
        // Nobody in this test asked about the wallet balances and the transaction fee
        // requirement, yet we got through with the final None.
        // How do we know? The mock agent didn't blow up while missing these
        // results
    }
}
