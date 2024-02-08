// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::inner::PaymentAdjusterInnerReal;
use crate::accountant::payment_adjuster::pre_adjustment_analyzer::PreAdjustmentAnalyzer;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::test_utils::make_wallet;
use itertools::Either;
use lazy_static::lazy_static;
use masq_lib::constants::MASQ_TOTAL_SUPPLY;
use masq_lib::logger::Logger;
use std::time::{Duration, SystemTime};

lazy_static! {
    pub static ref MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR: u128 =
        MASQ_TOTAL_SUPPLY as u128 * 10_u128.pow(18);
    pub static ref ONE_MONTH_LONG_DEBT_SEC: u64 = 30 * 24 * 60 * 60;
}

pub fn make_initialized_subject(
    now: SystemTime,
    cw_masq_balance_minor_opt: Option<u128>,
    logger_opt: Option<Logger>,
) -> PaymentAdjusterReal {
    let cw_masq_balance_minor = cw_masq_balance_minor_opt.unwrap_or(0);
    let logger = logger_opt.unwrap_or(Logger::new("test"));
    PaymentAdjusterReal {
        analyzer: PreAdjustmentAnalyzer::new(),
        inner: Box::new(PaymentAdjusterInnerReal::new(
            now,
            None,
            cw_masq_balance_minor,
        )),
        logger,
    }
}

pub fn make_extreme_accounts(
    months_of_debt_and_balance_minor: Either<(Vec<usize>, u128), Vec<(usize, u128)>>,
    now: SystemTime,
) -> Vec<PayableAccount> {
    let accounts_seeds: Vec<(usize, u128)> = match months_of_debt_and_balance_minor {
        Either::Left((vec_of_months, constant_balance)) => vec_of_months
            .into_iter()
            .map(|months| (months, constant_balance))
            .collect(),
        Either::Right(specific_months_and_specific_balance) => specific_months_and_specific_balance,
    };
    accounts_seeds
        .into_iter()
        .enumerate()
        .map(|(idx, (months_count, balance_minor))| PayableAccount {
            wallet: make_wallet(&format!("blah{}", idx)),
            balance_wei: balance_minor,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    months_count as u64 * (*ONE_MONTH_LONG_DEBT_SEC),
                ))
                .unwrap(),
            pending_payable_opt: None,
        })
        .collect()
}
