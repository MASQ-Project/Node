// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_scan_setup_msgs::PayablePaymentsSetup;
use crate::accountant::scanners::scan_mid_procedures::AwaitedAdjustment;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;
use std::time::SystemTime;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &PayablePaymentsSetup,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError>;

    fn adjust_payments(
        &self,
        setup: AwaitedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        _msg: &PayablePaymentsSetup,
        _logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError> {
        Ok(None)
    }

    fn adjust_payments(
        &self,
        _setup: AwaitedAdjustment,
        _now: SystemTime,
        _logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        todo!("this function is dead until the card GH-711 is being played")
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

#[derive(Debug, PartialEq, Eq)]
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
    use crate::accountant::scanners::payable_scan_setup_msgs::{
        PayablePaymentsSetup, PreliminaryContext, SingleTransactionFee, StageData,
    };
    use crate::accountant::test_utils::make_payable_account;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use web3::types::U256;

    #[test]
    fn search_for_indispensable_adjustment_always_returns_none() {
        init_test_logging();
        let test_name = "is_adjustment_required_always_returns_none";
        let mut payable_1 = make_payable_account(111);
        payable_1.balance_wei = 100_000_000;
        let mut payable_2 = make_payable_account(222);
        payable_2.balance_wei = 200_000_000;
        let non_required = PayablePaymentsSetup {
            qualified_payables: vec![payable_1.clone(), payable_2.clone()],
            this_stage_data_opt: Some(StageData::PreliminaryContext(PreliminaryContext {
                consuming_wallet_balances: ConsumingWalletBalances {
                    transaction_fee_currency_wei: U256::from(1_001_000_000_000_u64),
                    masq_tokens_wei: U256::from(301_000_000),
                },
                transaction_fee_specification: SingleTransactionFee {
                    gas_price_gwei: 10,
                    estimated_gas_limit: 50_000,
                },
                //gas amount to spend = 2 * 50_000 * 10 [gwei] = 1_000_000_000_000_000 wei
            })),
            response_skeleton_opt: None,
        };
        let logger = Logger::new(test_name);
        let subject = PaymentAdjusterReal::new();

        let non_required_result =
            subject.search_for_indispensable_adjustment(&non_required, &logger);

        let should_require = PayablePaymentsSetup {
            qualified_payables: vec![payable_1, payable_2],
            this_stage_data_opt: Some(StageData::PreliminaryContext(PreliminaryContext {
                consuming_wallet_balances: ConsumingWalletBalances {
                    transaction_fee_currency_wei: U256::from(999_000_000_000_u64),
                    masq_tokens_wei: U256::from(299_000_000),
                },
                transaction_fee_specification: SingleTransactionFee {
                    gas_price_gwei: 10,
                    estimated_gas_limit: 50_000,
                },
            })),
            response_skeleton_opt: None,
        };

        let should_require_result =
            subject.search_for_indispensable_adjustment(&should_require, &logger);

        assert_eq!(non_required_result, Ok(None));
        assert_eq!(should_require_result, Ok(None));
        TestLogHandler::default().exists_no_log_containing(test_name);
    }
}
