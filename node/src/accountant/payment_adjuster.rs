// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_scan_setup_msgs::PayablePaymentSetup;
use crate::accountant::scanners::scan_mid_procedures::AwaitingAdjustment;
use crate::sub_lib::blockchain_bridge::OutcomingPaymentsInstructions;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;
use std::time::SystemTime;

pub trait PaymentAdjuster {
    fn is_adjustment_required(
        &self,
        msg: &PayablePaymentSetup,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError>;

    fn adjust_payments(
        &self,
        setup: AwaitingAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutcomingPaymentsInstructions;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn is_adjustment_required(
        &self,
        _msg: &PayablePaymentSetup,
        _logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError> {
        Ok(None)
    }

    fn adjust_payments(
        &self,
        setup: AwaitingAdjustment,
        _now: SystemTime,
        _logger: &Logger,
    ) -> OutcomingPaymentsInstructions {
        OutcomingPaymentsInstructions {
            accounts: setup.original_msg.qualified_payables,
            response_skeleton_opt: setup.original_msg.response_skeleton_opt,
        }
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
    Gas { limiting_count: u16 },
    Both,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjuster, PaymentAdjusterReal};
    use crate::accountant::scanners::payable_scan_setup_msgs::{PayablePaymentSetup, StageData};
    use crate::accountant::scanners::scan_mid_procedures::AwaitingAdjustment;
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::ResponseSkeleton;
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, OutcomingPaymentsInstructions,
    };
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::SystemTime;
    use web3::types::U256;
    use StageData::FinancialDetails;

    #[test]
    fn is_adjustment_required_always_returns_none() {
        init_test_logging();
        let test_name = "is_adjustment_required_always_returns_none";
        let mut payable_1 = make_payable_account(111);
        payable_1.balance_wei = 100_000_000;
        let mut payable_2 = make_payable_account(222);
        payable_2.balance_wei = 200_000_000;
        let non_required = PayablePaymentSetup {
            qualified_payables: vec![payable_1.clone(), payable_2.clone()],
            this_stage_data_opt: Some(FinancialDetails {
                consuming_wallet_balances: ConsumingWalletBalances {
                    gas_currency_wei: U256::from(1_001_000_000_000_u64),
                    masq_tokens_wei: U256::from(301_000_000),
                },
                estimated_gas_limit_per_transaction: 50_000,
                desired_gas_price_gwei: 10,
                //gas amount to spent = 2 * 50_000 * 10 [gwei] = 1_000_000_000_000 wei
            }),
            response_skeleton_opt: None,
        };
        let logger = Logger::new(test_name);
        let subject = PaymentAdjusterReal::new();

        let non_required_result = subject.is_adjustment_required(&non_required, &logger);

        let should_require = PayablePaymentSetup {
            qualified_payables: vec![payable_1, payable_2],
            this_stage_data_opt: Some(FinancialDetails {
                consuming_wallet_balances: ConsumingWalletBalances {
                    gas_currency_wei: U256::from(999_000_000_000_u64),
                    masq_tokens_wei: U256::from(299_000_000),
                },
                estimated_gas_limit_per_transaction: 50_000,
                desired_gas_price_gwei: 10,
            }),
            response_skeleton_opt: None,
        };

        let should_require_result = subject.is_adjustment_required(&should_require, &logger);

        assert_eq!(non_required_result, Ok(None));
        assert_eq!(should_require_result, Ok(None));
        TestLogHandler::default().exists_no_log_containing(test_name);
    }

    #[test]
    fn adjust_payments_returns_accounts_unadjusted() {
        init_test_logging();
        let test_name = "is_adjustment_required_always_returns_none";
        let mut payable_1 = make_payable_account(111);
        payable_1.balance_wei = 123_000_000;
        let mut payable_2 = make_payable_account(222);
        payable_2.balance_wei = 234_000_000;
        let subject = PaymentAdjusterReal::new();
        let setup_msg = {
            let payable_1 = payable_1.clone();
            let payable_2 = payable_2.clone();
            move |adjustment: Adjustment, response_skeleton_opt: Option<ResponseSkeleton>| {
                AwaitingAdjustment {
                    original_msg: PayablePaymentSetup {
                        qualified_payables: vec![payable_1, payable_2],
                        this_stage_data_opt: Some(FinancialDetails {
                            consuming_wallet_balances: ConsumingWalletBalances {
                                gas_currency_wei: U256::from(123_456_789),
                                masq_tokens_wei: U256::from(111_222_333_444_u64),
                            },
                            estimated_gas_limit_per_transaction: 111_111,
                            desired_gas_price_gwei: 123,
                        }),
                        response_skeleton_opt,
                    },
                    adjustment,
                }
            }
        };
        let expected_msg =
            move |response_skeleton_opt: Option<ResponseSkeleton>| OutcomingPaymentsInstructions {
                accounts: vec![payable_1, payable_2],
                response_skeleton_opt,
            };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 111,
        });
        let logger = Logger::new(test_name);

        [
            (Adjustment::Gas { limiting_count: 1 }, None),
            (Adjustment::Gas { limiting_count: 1 }, response_skeleton_opt),
            (Adjustment::MasqToken, None),
            (Adjustment::MasqToken, response_skeleton_opt),
            (Adjustment::Both, None),
            (Adjustment::Both, response_skeleton_opt),
        ]
        .into_iter()
        .for_each(|(adjustment, response_skeleton_opt)| {
            let setup_msg = setup_msg.clone();
            let expected_msg = expected_msg.clone();
            assert_eq!(
                subject.adjust_payments(
                    setup_msg(adjustment, response_skeleton_opt),
                    SystemTime::now(),
                    &logger
                ),
                expected_msg(response_skeleton_opt)
            )
        });

        TestLogHandler::default().exists_no_log_containing(test_name);
    }
}
