// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_scanner::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::payable_scanner::payable_scanner_extension::PreparedAdjustment;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use masq_lib::logger::Logger;
use std::time::SystemTime;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError>;

    fn adjust_payments(
        &self,
        setup: PreparedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions;

    as_any_ref_in_trait!();
}

pub struct PaymentAdjusterReal {}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        _msg: &BlockchainAgentWithContextMessage,
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

    as_any_ref_in_trait_impl!();
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
    use crate::accountant::scanners::payable_scanner::data_structures::test_utils::make_priced_new_tx_templates;
    use crate::accountant::scanners::payable_scanner::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
    use crate::accountant::scanners::payable_scanner::payable_scanner_extension::test_utils::BlockchainAgentMock;
    use crate::accountant::test_utils::make_payable_account;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

    #[test]
    fn search_for_indispensable_adjustment_always_returns_none() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_always_returns_none";
        let payable = make_payable_account(123);
        let agent = BlockchainAgentMock::default();
        let priced_new_tx_templates = make_priced_new_tx_templates(vec![(payable, 111_111_111)]);
        let setup_msg = BlockchainAgentWithContextMessage {
            priced_templates: Either::Left(priced_new_tx_templates),
            agent: Box::new(agent),
            response_skeleton_opt: None,
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
