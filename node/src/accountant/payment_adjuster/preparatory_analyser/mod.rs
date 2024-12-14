// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod accounts_abstraction;

use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
    log_adjustment_by_service_fee_is_required, log_insufficient_transaction_fee_balance,
    log_transaction_fee_adjustment_ok_but_by_service_fee_undoable,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AffordableAndRequiredTxCounts, WeighedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::preparatory_analyser::accounts_abstraction::{
    BalanceProvidingAccount, DisqualificationLimitProvidingAccount,
};
use crate::accountant::payment_adjuster::{
    Adjustment, AdjustmentAnalysisReport, PaymentAdjusterError, ServiceFeeImmoderateInsufficiency,
    TransactionFeeImmoderateInsufficiency,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use ethereum_types::U256;
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::percentage::PurePercentage;

pub struct PreparatoryAnalyzer {}

impl PreparatoryAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze_accounts(
        &self,
        agent: &dyn BlockchainAgent,
        disqualification_arbiter: &DisqualificationArbiter,
        qualified_payables: Vec<QualifiedPayableAccount>,
        logger: &Logger,
    ) -> Result<Either<Vec<QualifiedPayableAccount>, AdjustmentAnalysisReport>, PaymentAdjusterError>
    {
        let number_of_accounts = qualified_payables.len();
        let cw_transaction_fee_balance_minor = agent.transaction_fee_balance_minor();
        let per_transaction_requirement_minor =
            agent.estimated_transaction_fee_per_transaction_minor();
        let gas_price_margin = agent.gas_price_margin();

        let transaction_fee_check_result = self
            .determine_transaction_count_limit_by_transaction_fee(
                cw_transaction_fee_balance_minor,
                gas_price_margin,
                per_transaction_requirement_minor,
                number_of_accounts,
                logger,
            );

        let cw_service_fee_balance_minor = agent.service_fee_balance_minor();
        let is_service_fee_adjustment_needed = Self::is_service_fee_adjustment_needed(
            &qualified_payables,
            cw_service_fee_balance_minor,
            logger,
        );

        if matches!(transaction_fee_check_result, Ok(None)) && !is_service_fee_adjustment_needed {
            return Ok(Either::Left(qualified_payables));
        }

        let prepared_accounts = Self::pre_process_accounts_for_adjustments(
            qualified_payables,
            disqualification_arbiter,
        );

        let service_fee_check_result = if is_service_fee_adjustment_needed {
            let error_factory = EarlyServiceFeeSingleTXErrorFactory::default();

            Self::check_adjustment_possibility(
                &prepared_accounts,
                cw_service_fee_balance_minor,
                error_factory,
            )
        } else {
            Ok(())
        };

        let transaction_fee_limitation_opt = Self::handle_errors_if_present(
            number_of_accounts,
            transaction_fee_check_result,
            service_fee_check_result,
        )?;

        let adjustment = match transaction_fee_limitation_opt {
            None => Adjustment::ByServiceFee,
            Some(transaction_count_limit) => Adjustment::BeginByTransactionFee {
                transaction_count_limit,
            },
        };

        Ok(Either::Right(AdjustmentAnalysisReport::new(
            adjustment,
            prepared_accounts,
        )))
    }

    fn handle_errors_if_present(
        number_of_accounts: usize,
        transaction_fee_check_result: Result<Option<u16>, TransactionFeeImmoderateInsufficiency>,
        service_fee_check_result: Result<(), ServiceFeeImmoderateInsufficiency>,
    ) -> Result<Option<u16>, PaymentAdjusterError> {
        match (transaction_fee_check_result, service_fee_check_result) {
            (Err(transaction_fee_check_error), Ok(_)) => Err(
                PaymentAdjusterError::EarlyNotEnoughFeeForSingleTransaction {
                    number_of_accounts,
                    transaction_fee_opt: Some(transaction_fee_check_error),
                    service_fee_opt: None,
                },
            ),
            (Err(transaction_fee_check_error), Err(service_fee_check_error)) => Err(
                PaymentAdjusterError::EarlyNotEnoughFeeForSingleTransaction {
                    number_of_accounts,
                    transaction_fee_opt: Some(transaction_fee_check_error),
                    service_fee_opt: Some(service_fee_check_error),
                },
            ),
            (Ok(_), Err(service_fee_check_error)) => Err(
                PaymentAdjusterError::EarlyNotEnoughFeeForSingleTransaction {
                    number_of_accounts,
                    transaction_fee_opt: None,
                    service_fee_opt: Some(service_fee_check_error),
                },
            ),
            (Ok(transaction_fee_limiting_count_opt), Ok(())) => {
                Ok(transaction_fee_limiting_count_opt)
            }
        }
    }

    pub fn recheck_if_service_fee_adjustment_is_needed(
        &self,
        weighed_accounts: &[WeighedPayable],
        cw_service_fee_balance_minor: u128,
        error_factory: LateServiceFeeSingleTxErrorFactory,
        logger: &Logger,
    ) -> Result<bool, PaymentAdjusterError> {
        if Self::is_service_fee_adjustment_needed(
            weighed_accounts,
            cw_service_fee_balance_minor,
            logger,
        ) {
            if let Err(e) = Self::check_adjustment_possibility(
                weighed_accounts,
                cw_service_fee_balance_minor,
                error_factory,
            ) {
                log_transaction_fee_adjustment_ok_but_by_service_fee_undoable(logger);
                Err(e)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    fn determine_transaction_count_limit_by_transaction_fee(
        &self,
        cw_transaction_fee_balance_minor: U256,
        gas_price_margin: PurePercentage,
        per_transaction_requirement_minor: u128,
        number_of_qualified_accounts: usize,
        logger: &Logger,
    ) -> Result<Option<u16>, TransactionFeeImmoderateInsufficiency> {
        let per_txn_requirement_minor_with_margin =
            gas_price_margin.add_percent_to(per_transaction_requirement_minor);

        let verified_tx_counts = Self::transaction_counts_verification(
            cw_transaction_fee_balance_minor,
            per_txn_requirement_minor_with_margin,
            number_of_qualified_accounts,
        );

        let max_tx_count_we_can_afford: u16 = verified_tx_counts.affordable;
        let required_tx_count: u16 = verified_tx_counts.required;

        if max_tx_count_we_can_afford == 0 {
            Err(TransactionFeeImmoderateInsufficiency {
                per_transaction_requirement_minor: per_txn_requirement_minor_with_margin,
                cw_transaction_fee_balance_minor,
            })
        } else if max_tx_count_we_can_afford >= required_tx_count {
            Ok(None)
        } else {
            log_insufficient_transaction_fee_balance(
                logger,
                required_tx_count,
                per_txn_requirement_minor_with_margin,
                cw_transaction_fee_balance_minor,
                max_tx_count_we_can_afford,
            );

            Ok(Some(max_tx_count_we_can_afford))
        }
    }

    fn transaction_counts_verification(
        cw_transaction_fee_balance_minor: U256,
        txn_fee_required_per_txn_minor: u128,
        number_of_qualified_accounts: usize,
    ) -> AffordableAndRequiredTxCounts {
        let max_possible_tx_count_u256 =
            cw_transaction_fee_balance_minor / U256::from(txn_fee_required_per_txn_minor);

        AffordableAndRequiredTxCounts::new(max_possible_tx_count_u256, number_of_qualified_accounts)
    }

    fn check_adjustment_possibility<AnalyzableAccounts, ErrorFactory, Error>(
        prepared_accounts: &[AnalyzableAccounts],
        cw_service_fee_balance_minor: u128,
        service_fee_error_factory: ErrorFactory,
    ) -> Result<(), Error>
    where
        AnalyzableAccounts: DisqualificationLimitProvidingAccount + BalanceProvidingAccount,
        ErrorFactory: ServiceFeeSingleTXErrorFactory<Error>,
    {
        let lowest_disqualification_limit =
            Self::find_lowest_disqualification_limit(prepared_accounts);

        // We cannot do much in this area but stepping in if the cw balance is zero or nearly
        // zero with the assumption that the debt with the lowest disqualification limit in
        // the set fits in the available balance. If it doesn't, we're not going to bother
        // the payment adjuster by that work, so it'll abort and no payments will come out.
        if lowest_disqualification_limit <= cw_service_fee_balance_minor {
            Ok(())
        } else {
            let analyzed_accounts_count = prepared_accounts.len();
            let required_service_fee_total =
                Self::compute_total_of_service_fee_required(prepared_accounts);
            let err = service_fee_error_factory.make(
                analyzed_accounts_count,
                required_service_fee_total,
                cw_service_fee_balance_minor,
            );
            Err(err)
        }
    }

    fn pre_process_accounts_for_adjustments(
        accounts: Vec<QualifiedPayableAccount>,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> Vec<AnalyzedPayableAccount> {
        accounts
            .into_iter()
            .map(|account| {
                let disqualification_limit =
                    disqualification_arbiter.calculate_disqualification_edge(&account);
                AnalyzedPayableAccount::new(account, disqualification_limit)
            })
            .collect()
    }

    fn compute_total_of_service_fee_required<Account>(payables: &[Account]) -> u128
    where
        Account: BalanceProvidingAccount,
    {
        sum_as(payables, |account| account.initial_balance_minor())
    }

    fn is_service_fee_adjustment_needed<Account>(
        qualified_payables: &[Account],
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> bool
    where
        Account: BalanceProvidingAccount,
    {
        let service_fee_totally_required_minor =
            Self::compute_total_of_service_fee_required(qualified_payables);
        (service_fee_totally_required_minor > cw_service_fee_balance_minor)
            .then(|| {
                log_adjustment_by_service_fee_is_required(
                    logger,
                    service_fee_totally_required_minor,
                    cw_service_fee_balance_minor,
                )
            })
            .is_some()
    }

    fn find_lowest_disqualification_limit<Account>(accounts: &[Account]) -> u128
    where
        Account: DisqualificationLimitProvidingAccount,
    {
        accounts
            .iter()
            .map(|account| account.disqualification_limit())
            .min()
            .expect("No account to consider")
    }
}

pub trait ServiceFeeSingleTXErrorFactory<E> {
    fn make(
        &self,
        number_of_accounts: usize,
        required_service_fee_total: u128,
        cw_service_fee_balance_minor: u128,
    ) -> E;
}

#[derive(Default)]
pub struct EarlyServiceFeeSingleTXErrorFactory {}

impl ServiceFeeSingleTXErrorFactory<ServiceFeeImmoderateInsufficiency>
    for EarlyServiceFeeSingleTXErrorFactory
{
    fn make(
        &self,
        _number_of_accounts: usize,
        total_service_fee_required_minor: u128,
        cw_service_fee_balance_minor: u128,
    ) -> ServiceFeeImmoderateInsufficiency {
        ServiceFeeImmoderateInsufficiency {
            total_service_fee_required_minor,
            cw_service_fee_balance_minor,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LateServiceFeeSingleTxErrorFactory {
    original_number_of_accounts: usize,
    original_service_fee_required_total_minor: u128,
}

impl LateServiceFeeSingleTxErrorFactory {
    pub fn new(unadjusted_accounts: &[WeighedPayable]) -> Self {
        let original_number_of_accounts = unadjusted_accounts.len();
        let original_service_fee_required_total_minor = sum_as(unadjusted_accounts, |account| {
            account.initial_balance_minor()
        });
        Self {
            original_number_of_accounts,
            original_service_fee_required_total_minor,
        }
    }
}

impl ServiceFeeSingleTXErrorFactory<PaymentAdjusterError> for LateServiceFeeSingleTxErrorFactory {
    fn make(
        &self,
        number_of_accounts: usize,
        _required_service_fee_total: u128,
        cw_service_fee_balance_minor: u128,
    ) -> PaymentAdjusterError {
        PaymentAdjusterError::LateNotEnoughFeeForSingleTransaction {
            original_number_of_accounts: self.original_number_of_accounts,
            number_of_accounts,
            original_service_fee_required_total_minor: self
                .original_service_fee_required_total_minor,
            cw_service_fee_balance_minor,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::disqualification_arbiter::{
        DisqualificationArbiter, DisqualificationGauge,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
    use crate::accountant::payment_adjuster::preparatory_analyser::{
        EarlyServiceFeeSingleTXErrorFactory, LateServiceFeeSingleTxErrorFactory,
        PreparatoryAnalyzer, ServiceFeeSingleTXErrorFactory,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        make_weighed_account, multiply_by_billion, multiply_by_billion_concise,
        DisqualificationGaugeMock,
    };
    use crate::accountant::payment_adjuster::{
        Adjustment, AdjustmentAnalysisReport, PaymentAdjusterError,
        ServiceFeeImmoderateInsufficiency,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::test_utils::{
        make_meaningless_analyzed_account, make_meaningless_qualified_payable,
    };
    use crate::accountant::QualifiedPayableAccount;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::TX_FEE_MARGIN_IN_PERCENT;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};
    use thousands::Separable;
    use web3::types::U256;

    fn test_adjustment_possibility_nearly_rejected(
        test_name: &str,
        disqualification_gauge: DisqualificationGaugeMock,
        original_accounts: [QualifiedPayableAccount; 2],
        cw_service_fee_balance: u128,
    ) {
        init_test_logging();
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let disqualification_gauge = double_mock_results_queue(disqualification_gauge)
            .determine_limit_params(&determine_limit_params_arc);
        let total_amount_required: u128 = sum_as(original_accounts.as_slice(), |account| {
            account.bare_account.balance_wei
        });
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let subject = PreparatoryAnalyzer {};
        let blockchain_agent = BlockchainAgentMock::default()
            .gas_price_margin_result(*TX_FEE_MARGIN_IN_PERCENT)
            .transaction_fee_balance_minor_result(U256::MAX)
            .estimated_transaction_fee_per_transaction_minor_result(123456)
            .service_fee_balance_minor_result(cw_service_fee_balance);

        let result = subject.analyze_accounts(
            &blockchain_agent,
            &disqualification_arbiter,
            original_accounts.clone().to_vec(),
            &Logger::new(test_name),
        );

        let expected_adjustment_analysis = {
            let analyzed_accounts = PreparatoryAnalyzer::pre_process_accounts_for_adjustments(
                original_accounts.to_vec(),
                &disqualification_arbiter,
            );
            AdjustmentAnalysisReport::new(Adjustment::ByServiceFee, analyzed_accounts)
        };
        assert_eq!(result, Ok(Either::Right(expected_adjustment_analysis)));
        let determine_limit_params = determine_limit_params_arc.lock().unwrap();
        let account_1 = &original_accounts[0];
        let account_2 = &original_accounts[1];
        let expected_params = vec![
            (
                account_1.bare_account.balance_wei,
                account_1.payment_threshold_intercept_minor,
                account_1.creditor_thresholds.permanent_debt_allowed_minor,
            ),
            (
                account_2.bare_account.balance_wei,
                account_2.payment_threshold_intercept_minor,
                account_2.creditor_thresholds.permanent_debt_allowed_minor,
            ),
        ];
        assert_eq!(&determine_limit_params[0..2], expected_params);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Mature payables amount to {} MASQ wei while the consuming wallet \
            holds only {} wei. Adjustment in their count or balances is necessary.",
            total_amount_required.separate_with_commas(),
            cw_service_fee_balance.separate_with_commas()
        ));
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_slightly_bigger() {
        let mut account_1 = make_meaningless_qualified_payable(111);
        account_1.bare_account.balance_wei = multiply_by_billion_concise(1.0);
        let mut account_2 = make_meaningless_qualified_payable(333);
        account_2.bare_account.balance_wei = multiply_by_billion_concise(2.0);
        let cw_service_fee_balance = multiply_by_billion_concise(0.75) + 1;
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(multiply_by_billion_concise(0.75))
            .determine_limit_result(multiply_by_billion_concise(1.5));
        let original_accounts = [account_1, account_2];

        test_adjustment_possibility_nearly_rejected(
            "adjustment_possibility_nearly_rejected_when_cw_balance_slightly_bigger",
            disqualification_gauge,
            original_accounts,
            cw_service_fee_balance,
        )
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_equal() {
        let mut account_1 = make_meaningless_qualified_payable(111);
        account_1.bare_account.balance_wei = multiply_by_billion_concise(2.0);
        let mut account_2 = make_meaningless_qualified_payable(333);
        account_2.bare_account.balance_wei = multiply_by_billion_concise(1.0);
        let cw_service_fee_balance = multiply_by_billion_concise(0.75);
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(multiply_by_billion_concise(1.5))
            .determine_limit_result(multiply_by_billion_concise(0.75));
        let original_accounts = [account_1, account_2];

        test_adjustment_possibility_nearly_rejected(
            "adjustment_possibility_nearly_rejected_when_cw_balance_equal",
            disqualification_gauge,
            original_accounts,
            cw_service_fee_balance,
        )
    }

    fn test_not_enough_for_even_the_least_demanding_account_causes_error<F, ErrorFactory, Error>(
        error_factory: ErrorFactory,
        expected_error_preparer: F,
    ) where
        F: FnOnce(usize, u128, u128) -> Error,
        ErrorFactory: ServiceFeeSingleTXErrorFactory<Error>,
        Error: Debug + PartialEq,
    {
        let mut account_1 = make_meaningless_analyzed_account(111);
        account_1.qualified_as.bare_account.balance_wei = 2_000_000_000;
        account_1.disqualification_limit_minor = 1_500_000_000;
        let mut account_2 = make_meaningless_analyzed_account(222);
        account_2.qualified_as.bare_account.balance_wei = 1_000_050_000;
        account_2.disqualification_limit_minor = 1_000_000_101;
        let mut account_3 = make_meaningless_analyzed_account(333);
        account_3.qualified_as.bare_account.balance_wei = 1_000_111_111;
        account_3.disqualification_limit_minor = 1_000_000_222;
        let cw_service_fee_balance = 1_000_000_100;
        let supplied_accounts = vec![account_1, account_2, account_3];
        let supplied_accounts_count = supplied_accounts.len();
        let service_fee_total_of_the_known_set = 2_000_000_000 + 1_000_050_000 + 1_000_111_111;

        let result = PreparatoryAnalyzer::check_adjustment_possibility(
            &supplied_accounts,
            cw_service_fee_balance,
            error_factory,
        );

        let expected_error = expected_error_preparer(
            supplied_accounts_count,
            service_fee_total_of_the_known_set,
            cw_service_fee_balance,
        );
        assert_eq!(result, Err(expected_error))
    }

    #[test]
    fn not_enough_for_even_the_least_demanding_account_error_right_after_positive_tx_fee_check() {
        let error_factory = EarlyServiceFeeSingleTXErrorFactory::default();

        let expected_error_preparer =
            |_, total_amount_demanded_in_accounts_in_place, cw_service_fee_balance_minor| {
                ServiceFeeImmoderateInsufficiency {
                    total_service_fee_required_minor: total_amount_demanded_in_accounts_in_place,
                    cw_service_fee_balance_minor,
                }
            };

        test_not_enough_for_even_the_least_demanding_account_causes_error(
            error_factory,
            expected_error_preparer,
        )
    }

    #[test]
    fn not_enough_for_even_the_least_demanding_account_error_right_after_tx_fee_accounts_dump() {
        let original_accounts = vec![
            make_weighed_account(123),
            make_weighed_account(456),
            make_weighed_account(789),
            make_weighed_account(1011),
        ];
        let original_number_of_accounts = original_accounts.len();
        let initial_sum = sum_as(&original_accounts, |account| {
            account.initial_balance_minor()
        });
        let error_factory = LateServiceFeeSingleTxErrorFactory::new(&original_accounts);
        let expected_error_preparer = |number_of_accounts, _, cw_service_fee_balance_minor| {
            PaymentAdjusterError::LateNotEnoughFeeForSingleTransaction {
                original_number_of_accounts,
                number_of_accounts,
                original_service_fee_required_total_minor: initial_sum,
                cw_service_fee_balance_minor,
            }
        };

        test_not_enough_for_even_the_least_demanding_account_causes_error(
            error_factory,
            expected_error_preparer,
        )
    }

    #[test]
    fn accounts_analyzing_works_even_for_weighed_payable() {
        init_test_logging();
        let test_name = "accounts_analyzing_works_even_for_weighed_payable";
        let balance_1 = multiply_by_billion(2_000_000);
        let mut weighed_account_1 = make_weighed_account(123);
        weighed_account_1
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = balance_1;
        let balance_2 = multiply_by_billion(3_456_000);
        let mut weighed_account_2 = make_weighed_account(456);
        weighed_account_2
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = balance_2;
        let accounts = vec![weighed_account_1, weighed_account_2];
        let service_fee_totally_required_minor = balance_1 + balance_2;
        let cw_service_fee_balance_minor = service_fee_totally_required_minor + 1;
        let error_factory = LateServiceFeeSingleTxErrorFactory::new(&accounts);
        let logger = Logger::new(test_name);
        let subject = PreparatoryAnalyzer::new();

        [(0, false), (1, false), (2, true)].iter().for_each(
            |(subtrahend_from_cw_balance, expected_result)| {
                let service_fee_balance = cw_service_fee_balance_minor - subtrahend_from_cw_balance;
                let result = subject
                    .recheck_if_service_fee_adjustment_is_needed(
                        &accounts,
                        service_fee_balance,
                        error_factory.clone(),
                        &logger,
                    )
                    .unwrap();
                assert_eq!(result, *expected_result);
            },
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Mature payables amount to {} MASQ wei while the consuming wallet \
            holds only {}",
            service_fee_totally_required_minor.separate_with_commas(),
            (cw_service_fee_balance_minor - 2).separate_with_commas()
        ));
    }

    #[test]
    fn construction_of_error_context_with_accounts_dumped_works() {
        let balance_1 = 1234567;
        let mut account_1 = make_weighed_account(123);
        account_1
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = balance_1;
        let balance_2 = 999888777;
        let mut account_2 = make_weighed_account(345);
        account_2
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = balance_2;
        let weighed_accounts = vec![account_1, account_2];

        let result = LateServiceFeeSingleTxErrorFactory::new(&weighed_accounts);

        assert_eq!(
            result,
            LateServiceFeeSingleTxErrorFactory {
                original_number_of_accounts: 2,
                original_service_fee_required_total_minor: balance_1 + balance_2
            }
        )
    }

    fn double_mock_results_queue(mock: DisqualificationGaugeMock) -> DisqualificationGaugeMock {
        let originally_prepared_results = (0..2)
            .map(|_| mock.determine_limit(0, 0, 0))
            .collect::<Vec<_>>();
        originally_prepared_results
            .into_iter()
            .cycle()
            .take(4)
            .fold(mock, |mock, result_to_be_added| {
                mock.determine_limit_result(result_to_be_added)
            })
    }
}
